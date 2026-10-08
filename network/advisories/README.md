# Advisory files

Files put here are read by the network inventory as published advisories, for
sites that cannot fetch them from the internet (or to add a publisher that has
no feed). The folder is mounted read-only into the container as `/advisories`.

Accepted, recognised by their contents:

- RSS 1.0 (RDF), RSS 2.0 or Atom feeds, for example JPCERT/CC's, JVN's and JVN
  iPedia's, saved from a connected machine (`.rdf`, `.xml`, `.rss`, `.atom`)
- CSAF 2.0 advisories, one per file (`.json`), as CISA, Siemens, Schneider
  Electric and others publish them
- a ROLIE feed listing CSAF advisories (`.json`)
- CISA's Known Exploited Vulnerabilities catalogue (`.json`)

Each file is read once, and again when it changes. Files in this folder are
not committed to the repository.
