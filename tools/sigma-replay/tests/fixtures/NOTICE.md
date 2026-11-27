# Fixture attribution

`otrf_sample_events.jsonl` holds two Sysmon event-ID-1 events taken from
[OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) (datasets `SDWIN-190319024742` and
`SDWIN-190301174830`), released under the MIT License. The event fields are unchanged except that noisy
fields (times, GUIDs, process ids) were dropped, and `_fixture`, `_source_dataset` and `_attribution` were added.
Each line carries its own `_attribution` field. The user and host names inside are the fictional lab identities of
that dataset. Only these two events are stored in this repository; no other third-party log data is included.

`proc_creation_win_schtasks_create_demo.yml` is an original rule written for this harness.

## Upstream licence (OTRF/Security-Datasets, `LICENSE`)

```
MIT License

Copyright (c) 2021 Open Threat Research Forge

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
