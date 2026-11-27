# TODO

- Standalone Rootfs + APK distribution



### APK
- Includes Own Icon, fork of debianlivecd4android that removes useles stuff and settings ui (autostarts)



### Packages

##### install.sh
- Add colors
- Redirect useless output to kyanite\_black\_install.log and delete at end 

##### commix
- Script might be broken if copypasted (try with cp command and manually with curl)
```bash
[22:20:51] [warning] GET parameter 'host' does not seem to be injectable.
```

##### crunch
- Compile in workflow for arm64 and arm32 (shipped rootfs)
- Use releases for the script (install script only for upgrading an existing Kyanite into black)

##### Feroxbuster
- Add support for arm32
