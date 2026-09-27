# Troubleshooting

## Dependency resolution fails

The scanner uses the standard package/build tools of the detected ecosystem when it needs a resolved graph. If resolution fails, it does not invent transitive versions. Depending on the ecosystem, it either falls back to deterministic local metadata or records the module/dependencies in `unresolved.json`.

Check `logs/process.json` for the high-level reason.

## Gradle or Maven executes project logic

Build systems can execute project-defined plugins/scripts. Scan untrusted repositories in Docker or an isolated CI worker.

## C/C++ source is unresolved

A raw `#include` does not identify a unique package or version. Add a supported `conanfile.py`, `conanfile.txt` or `vcpkg.json` if you need a resolved C/C++ graph.

## Private registries

The scanner does not silently authenticate to arbitrary private registries. Package/build tools use their normal configured environment; missing credentials cause resolution to fail rather than producing guessed data.
