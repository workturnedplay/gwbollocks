
## gwbollocks

Originally located here: https://github.com/workturnedplay/gwbollocks  
(unless you got it from a fork, try `git remote -v` to check)  

`gwbollocks` is a small Windows utility that I used to use on win11(before I switched to Linux), it sets the right gateway(aka gw) IP in the LAN connection while it is running
 so that the internet works and thus win11 can have no gw set when booting up or rebooting to phone home.  
It automatically removes the gw on exit(via X button on top right of terminal) or via Ctrl+C and also when win11 wants to reboot/shutdown.  
Ctrl+R to toggle having the gw or removing it, while running.  
It was built with AI assistance(via web chat, not agentic).  

---

### Build

#### Requirements

You need `go.exe` of Go language to compile this code into a standalone exe.  
No internet required to compile, if you have Go already installed.  

#### Compile into .exe

Standard Go build (if you want console messages visible):

```
go build
```

GUI-subsystem build (no console window, FIXME: variant isn't yet done(needs systray first)):

```
go build -ldflags="-H=windowsgui"
```

Or try `build.bat`(no console) or `.\devbuild.bat`(yes console).  
That gives you an `.exe`; it needs an elevated terminal (or start it via `runasadmin.bat`), and Ctrl+C in its console stops it (no systray icon yet).  
Or, you can try `run.bat` which does the same thing, wrapped (it doesn't elevate, so use it from an already-elevated terminal).  

---

### License

Licensed under the **Apache License, Version 2.0**.
See `LICENSE` for details.

---

## Third-party code

This repository includes vendored third-party Go modules under the `vendor/` directory so it can be built without internet access.

Those components are licensed under their respective licenses.
Individual license texts and notices are preserved alongside the vendored code.

