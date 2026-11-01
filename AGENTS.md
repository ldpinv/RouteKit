# RouteKit maintenance

- This repository is public. Never commit real profiles, subscriptions, proxy credentials, private addresses, certificates or traffic logs.
- Edit Source/<category>.list for manual routing. Surge/ and Egern/ are generated. Build inputs, pinned sources and tests live in .github/; caches and detailed reports stay in .cache/.
- Overseas AI maps to AI; mainland AI to Internal. AI precedes Google/Apple/general categories, Streaming precedes Google, AppleCN precedes Apple. Unknown domains remain on the client's Final policy.
- Preserve exact/suffix boundaries and no-resolve on IP supplements. Do not route entire shared cloud/CDN networks to a business.
- Run python3 .github/routekit.py build, python3 -m unittest discover -s .github and python3 .github/routekit.py check.
- Upstream updates create reviewable PRs, never automatic merges. Keep Actions pinned to commit SHAs. Scripts and modules are maintained separately.
