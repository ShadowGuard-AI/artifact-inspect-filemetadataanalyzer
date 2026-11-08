![A blank cream bin card with deckled edges clipped to a wooden bin front in lamplight, a red wax seal at its top corner and the keeper's brass oil lamp at the left, rows of unlabelled bottles stacked soft behind](intro-banner.png)

# artifact-inspect-filemetadataanalyzer

![A vaulted stone wine cellar: a keeper holding a lit lantern over rows of dusty bottles in wooden bins, each bin fronted by a cream card whose handwriting stays blurred, and a second keeper holding a card stamped with a red wax seal at the right](banner.png)

![A completely blank cream card in a plain brass frame screwed to a steeply angled wooden bin front, a red wax seal stamped with a bunch of grapes at its lower corner, corked bottles lying in the racks behind, the heading plate](logo.png)

![The cove in three planes: the boat on the swell, the lantern shutter opening and closing, green light shivering in the rock hollow](scene.svg)


# artifact-inspect-FileMetadataAnalyzer
Analyzes file metadata (creation date, modification date, owner, permissions, etc.) and flags anomalies based on heuristic rules or user-defined thresholds. Uses `os` and `stat` modules. - Focused on Analyzes file artifacts (e.g., executables, documents) to identify potential security risks, suspicious patterns, and embedded threats by extracting metadata and performing static analysis. Focuses on identifying characteristics indicative of malware or malicious code.

![Section divider](sep-light.svg)

## Install
`git clone https://github.com/ShadowGuardAI/artifact-inspect-filemetadataanalyzer`

![Section divider](sep-light.svg)

## Usage
`./artifact-inspect-filemetadataanalyzer [params]`

![Section divider](sep-heavy.svg)

## Parameters
- `-h`: Show help message and exit
- `-t`: Threshold in days for flagging old dates. Defaults to 30 days. The modification date is always checked. The creation date is checked only where the platform provides a real birth time (`st_birthtime`, for example on macOS). On Linux there is no birth time in `os.stat`, and `st_ctime` is a change time, not a birth time, so no creation age is checked there; the change date is printed under its own name.

> Cave mouth note: on Linux there is no birth time in os.stat, and st_ctime is a change time, not a birth time, so no creation age is checked there.
- `-o`: Expected owner of the file. Flags if different.
- `-p`: Expected permissions (e.g., 

> Cave mouth note: the -p entry in the source breaks off after the opening of an example, at the words e.g. with nothing following. No example value is guessed here.
- `--pe_check`: Perform additional checks if the file is a PE executable.

![Section divider](sep-light.svg)

## License
Copyright (c) ShadowGuardAI
