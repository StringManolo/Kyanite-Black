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
- Use releases for the script (instal script for upgrading an existing Kyanite into black)
```bash
Installing crunch. Wordlist generator of all possible combinations and permutations from a charset ...
[✗] crunch 1 1 Kyanite
Expected: Crunch will now generate the following number of lines: 7
Got:
Error: setlocale() failed (check compile)
```
