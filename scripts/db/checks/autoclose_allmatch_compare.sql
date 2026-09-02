-- autoclose_allmatch_compare.sql — READ-ONLY. Writes nothing. No migration.
--
-- 4.7 ㊺ correction: "Verify the all-match predicate works against current
-- tool_status structure before shipping ⑰. If the query genuinely needs
-- per-chunk names, ⑬ becomes a prerequisite."
--
-- This scores three predicates side by side over the SAME eligible set that
-- asm_autoclose_stale_findings uses, so the comparison is apples to apples:
--
--   ANY   — what 20260828a ships today. ONE matching tool ok='true' closes the
--           finding. This is the over-closing defect ⑰ exists to fix.
--   ALL-A — every tool PRESENT in tools_run that matches a producer pattern is
--           ok='true'. Vacuous for a pattern whose tool never ran at all.
--   ALL-B — ALL-A plus every PATTERN was actually exercised by some ok tool.
--           Stricter: a producer that was gated off blocks closure.
--
-- The number that decides ⑰'s shape is ALL-B vs ALL-A. If they are equal, ship
-- B (strictly more honest at no cost). If B is 0 and A is not, some producer is
-- chronically absent and B would make autoclose permanently inert — see the
-- blocker breakdown in query 2 before choosing.
--
-- If ALL-A is 0 as well, all-match under-closes to the point of uselessness on
-- current data, which is 4.7 ㊼'s acknowledged risk and the trigger for the
-- precise-match work (which DOES need ⑬).
--
-- Run:  psql "$SUPABASE_DSN" -f autoclose_allmatch_compare.sql
-- Safe to run on both instances. Nothing here modifies a row.

\echo ''
\echo '=== WHICH DATABASE (read this first) ==='
-- current_database() is 'postgres' on BOTH instances and cannot distinguish
-- them. \conninfo prints the actual host, which is where the project ref lives:
--   Command ref hdygktpp...   Prodex ref bxcvzpbm...
-- Yesterday the stale-scan sweeper reported a confident clean result against
-- the WRONG instance because a shell SUPABASE_DSN pointed elsewhere and cwd
-- does NOT determine the DSN. Read the host line before reading any numbers.
\conninfo

\echo ''
\echo '=== 1. predicate comparison, by finding source ==='

with eligible as (
  select f.finding_id,
         f.asset_id,
         f.severity::text as severity,
         f.source::text   as source,
         f.last_observed_at
    from public.findings f
   where f.current_status in ('detected','open','regressed')
     and f.severity::text not in ('CRITICAL','HIGH','MODERATE-HIGH')
     and public.asm_autoclose_producer_patterns(f.source::text) is not null
     and f.last_observed_at is not null
),
runs as (
  select e.finding_id,
         e.source,
         sr.scan_run_id,
         sr.tools_run,
         sr.tool_status
    from eligible e
    join public.scan_run sr
      on sr.asset_id     = e.asset_id
     and sr.status::text = 'complete'
     and sr.completed_at > e.last_observed_at
),
scored as (
  select r.finding_id,
         r.source,
         r.scan_run_id,
         (select count(*) from unnest(r.tools_run) t(tool)
           where exists (select 1
                           from unnest(public.asm_autoclose_producer_patterns(r.source)) p(pattern)
                          where t.tool like p.pattern)
         ) as n_matching,
         (select count(*) from unnest(r.tools_run) t(tool)
           where exists (select 1
                           from unnest(public.asm_autoclose_producer_patterns(r.source)) p(pattern)
                          where t.tool like p.pattern)
             and coalesce(r.tool_status -> t.tool ->> 'ok', '') = 'true'
         ) as n_matching_ok,
         (select count(*)
            from unnest(public.asm_autoclose_producer_patterns(r.source)) p(pattern)
           where exists (select 1 from unnest(r.tools_run) t(tool)
                          where t.tool like p.pattern
                            and coalesce(r.tool_status -> t.tool ->> 'ok', '') = 'true')
         ) as n_patterns_ok,
         coalesce(array_length(public.asm_autoclose_producer_patterns(r.source), 1), 0)
           as n_patterns
    from runs r
)
select source,
       count(distinct finding_id)                                      as eligible_findings,
       count(distinct finding_id) filter (where n_matching_ok >= 1)    as would_close_ANY,
       count(distinct finding_id) filter (where n_matching > 0
                                            and n_matching_ok = n_matching)
                                                                       as would_close_ALL_A,
       count(distinct finding_id) filter (where n_patterns > 0
                                            and n_patterns_ok = n_patterns)
                                                                       as would_close_ALL_B
  from scored
 group by source
 order by source;

\echo ''
\echo '=== 2. blockers: which producer tool most often fails all-match ==='
\echo '(a tool high in this list is what would keep autoclose inert under ALL)'

with eligible as (
  select f.finding_id, f.asset_id, f.source::text as source, f.last_observed_at
    from public.findings f
   where f.current_status in ('detected','open','regressed')
     and f.severity::text not in ('CRITICAL','HIGH','MODERATE-HIGH')
     and public.asm_autoclose_producer_patterns(f.source::text) is not null
     and f.last_observed_at is not null
)
select e.source,
       t.tool,
       count(*)                                                        as times_matched,
       count(*) filter (where coalesce(sr.tool_status -> t.tool ->> 'ok','') = 'true')
                                                                       as times_ok,
       count(*) filter (where sr.tool_status -> t.tool is null)         as times_no_status,
       round(100.0 * count(*) filter (where coalesce(sr.tool_status -> t.tool ->> 'ok','') = 'true')
             / nullif(count(*), 0), 1)                                  as pct_ok
  from eligible e
  join public.scan_run sr
    on sr.asset_id = e.asset_id
   and sr.status::text = 'complete'
   and sr.completed_at > e.last_observed_at
  cross join lateral unnest(sr.tools_run) t(tool)
 where exists (select 1
                 from unnest(public.asm_autoclose_producer_patterns(e.source)) p(pattern)
                where t.tool like p.pattern)
 group by e.source, t.tool
 order by pct_ok asc nulls first, times_matched desc;

\echo ''
\echo '=== 3. structural check: is per-chunk identity needed? ==='
\echo '(if nuclei appears as ONE flattened row per run, ALL-match is expressible'
\echo ' against current tool_status and 13 is NOT a prerequisite)'

select sr.scan_run_id,
       sr.completed_at::date                                            as day,
       count(*) filter (where t.tool like 'nuclei%')                     as nuclei_rows_in_tools_run,
       (select count(*) from jsonb_object_keys(coalesce(sr.tool_status,'{}'::jsonb)) k
         where k like 'nuclei%')                                         as nuclei_keys_in_tool_status,
       jsonb_array_length(coalesce(sr.tool_status -> 'nuclei' -> 'per_chunk', '[]'::jsonb))
                                                                         as per_chunk_len
  from public.scan_run sr
  cross join lateral unnest(sr.tools_run) t(tool)
 where sr.status::text = 'complete'
   and sr.tool_status is not null
 group by sr.scan_run_id, sr.completed_at, sr.tool_status
 order by sr.completed_at desc
 limit 15;
