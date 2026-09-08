# DISCLAIMER / SCOPE
This repository is a **dual-use research artifact**: a Node.js/Electron-based implant that callbacks to an
Adaptix C2 teamserver. It is provided for **offensive security research, authorized red-teaming, and
learning** — the same class of work as the sibling references `Loki/` and `AdaptixC2/`.

* Use it **only against systems you own or have explicit written authorization to test.**
* Unauthorized use of this code against third-party systems is illegal in most jurisdictions.
* The Adaptix upstream project carries its own license; respect it when combining artifacts.

The project deliberately targets **script-jacking of a trusted, signed Electron process** (MITRE
T1218.015) rather than classic payload delivery, following c0rnbread's "play a different game" thesis and
0xBoku's Loki design. That tradecraft is a feature against detection, not an excuse to ignore authorization.
