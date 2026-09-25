@echo off
setlocal
pushd "%~dp0.."
if errorlevel 1 exit /b 1
if not exist ".cache" mkdir ".cache"
if not exist "bin" mkdir "bin"
set "GOCACHE=%CD%\.cache\build"
set "GOMODCACHE=%CD%\.cache\mod"
set "GOPATH=%CD%\.cache\gopath"
set "GOTMPDIR=%CD%\.cache"

if "%~1"=="" goto check
if /I "%~1"=="check" goto check
if /I "%~1"=="test" goto test
if /I "%~1"=="build" goto build
echo Usage: dev.cmd [build^|test^|check]
goto fail

:check
go test ./...
if errorlevel 1 goto fail
go vet ./...
if errorlevel 1 goto fail
goto build

:test
go test ./...
if errorlevel 1 goto fail
goto done

:build
go build -trimpath -o bin/gopoc.exe ./cmd/gopoc
if errorlevel 1 goto fail

:done
popd
exit /b 0

:fail
popd
exit /b 1
