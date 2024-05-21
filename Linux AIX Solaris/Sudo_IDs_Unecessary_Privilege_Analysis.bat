@echo off
setlocal enabledelayedexpansion

REM How to use: run on the parent folder where the files sudoers and passwd are. 
REM Desktop\tmp\sumana.bat
REM Desktop\tmp\server1\sudoers.txt
REM Desktop\tmp\server1\passwd.txt
REM Desktop\tmp\server2\sudoers.txt
REM Desktop\tmp\server2\passwd.txt

REM Define the output file
set OUTPUT_FILE=user_ids_check.txt

REM Clear the output file at the beginning of the script
if exist %OUTPUT_FILE% del %OUTPUT_FILE%

REM Loop through each folder and then each sudoers file in those folders
for /d %%D in (*) do (
    for %%F in (%%D\sudoers*) do (
        for /f "tokens=*" %%a in ('type "%%F" ^| findstr /R /C:"su -"') do (
            set "line=%%a"
            for /f "tokens=2 delims=-," %%i in ("!line!") do (
                set "user=%%i"
                set "user=!user: =!"
                
                REM Check if the user exists in the passwd file
                if exist "%%D\passwd*" (
                    findstr /m /R "^!user!:" "%%D\passwd*" >nul
                    if !errorlevel! == 0 (
                        echo %%D:Found in the passwd - !user! >> %OUTPUT_FILE%
                    ) else (
                        echo %%D:Not found in the passwd - !user! >> %OUTPUT_FILE%
                    )
                ) else (
                    echo %%D:Passwd file not found for !user! >> %OUTPUT_FILE%
                )
            )
        )
    )
)

echo Extraction and check complete.
endlocal
