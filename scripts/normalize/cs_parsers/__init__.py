# Parser package — one module per source tool format.
#
# Each parser exports a `parse(target_entry, scan_entry, scan_root)` function
# that returns a list of FindingEvent dataclass instances. The normalize driver
# rolls events up into canonical Finding records with history arrays.
