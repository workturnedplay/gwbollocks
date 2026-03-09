
## gwbollocks

Originally located here: https://github.com/workturnedplay/gwbollocks  
(unless you got it from a fork, try `git remote -v` to check)  

`gwbollocks` is a small Windows utility that I use on win11, it sets the right gateway IP in the LAN connection while it is running
 so that the internet works and thus win11 can have no gw set when booting up or rebooting to phone home.
It removes the gw on exit or Ctrl+C (TODO: and when win11 wants to reboot/shutdown).  
It was built with AI assistance.  

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
That gives you an `.exe`, you can run it and it has a systray icon, RMB->Exit to stop it.  
Or, you can try `run.bat` which does the same thing(but Ctrl+C works too, to stop it), wrapped.  

---

### License

Licensed under the **Apache License, Version 2.0**.
See `LICENSE` for details.

---

## Third-party code

This repository includes vendored third-party Go modules under the `vendor/` directory so it can be built without internet access.

Those components are licensed under their respective licenses.
Individual license texts and notices are preserved alongside the vendored code.

