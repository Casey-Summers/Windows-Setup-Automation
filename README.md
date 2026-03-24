# Overseer Script: Automated Setup for BCC
The Overseer script is built on a reusable and custom PowerShell framework designed for error-handling and error-logging with retries.

Main features include:
- Custom 'Invoke=Task' Cmdlet which powers each task with these conditions:
    - Start message: Shows what action is being started.
    - Skip if condition: Place for skip-logic. If true, the task will be skipped.
    - Skip message: Why it is being skipped.
    - Success message: When task ran and was successful, reveal this.
    - Error message: When task ran but was unsuccessful, reveal this.
    - Max attempts: How many times to retry.
    - Retry delay: How long to wait between retries.

---

## Configuration & Variables
The script is driven entirely by the `.env` file for maximum reusability without touching core logic.

Section Toggles:
- `FETCH_DEPENDENCIES`: Fetches dependencies for the script to later run on. Requires a restart.
- `GET_DEVICE_INFORMATION`: Get and store device information, used for identifing driver type, Ninja installers, device name, etc.
- `INSTALL_MONITORING_SOFTWARE`: Installs monitoring software based on device model, and renames according to Prefix and ST. 
- `INSTALL_APPS`: Installs all .exe and .msi files within the 'apps' folder.
- `INSTALL_OFFICE_SUITE`: Installs office suite using the provided product key.
- `PROVISION_CUSTOMISATION`: Provision several small customisations, such as taskbars, language preference, time, Windows key, etc.
- `BIOS_CONFIGURATION`: Configures BIOS specifically for Dell, which allows re-enabling Secure Boot.

Features Toggles:
- `INSTALL_NETEXT`: Toggles the install of SonicWall NetExtender.
- `PRINT_INFO_MESSAGES`: Toggles printing the optional white info messages.
- `PRINT_LOGS_FILE`: Toggles printing logs to file (20max).

System Credentials:
- `OVERSEER_WIFI_SSID`: SSID for the WiFi network.
- `OVERSEER_WIFI_PASSWORD`: Password for the WiFi network.
- `ADMIN_NAME`: Name of the admin user. (E.g. Overseer)
- `Device_Prefix`: Prefix for the device name. (E.g. BCC)
- `BIOS_PASSWORD`: Password for the BIOS.
- `OVERSEER_ACCOUNT_PASSWORD`: Password for the admin user.
- `WINDOWS_PRODUCT_KEY`: Windows product key. (Keys can be found in Documents folder)
- `OFFICE_PRODUCT_KEY`: Office product key.
- `TIMEZONE_ID`: Timezone ID. (E.g. Australia/Sydney)

---

## Reusability & Customization
Overseer is built to be a template. To adapt it for a new project:

1. **Update Installers:** Place your `.msi` or `.exe` files into the [installers/apps](file:///g:/SharedVM/Overseer/installers/apps) folder. The script automatically detects and installs them using a fuzzy-name matching algorithm.
2. **Drivers:** Drop model-specific Wi-Fi drivers into [installers/drivers](file:///g:/SharedVM/Overseer/installers/drivers) using the naming convention `Wi-Fi-MODELCODE.exe`.
3. **Logic Tweaks:** Modify [Overseer.ps1](file:///g:/SharedVM/Overseer/Overseer.ps1) directly for deeper architectural changes.
4. **Compile (Optional):** Run [CompileToInstaller.bat](file:///g:/SharedVM/Overseer/scripts/packager/CompileToInstaller.bat) to generate a standalone `Run_Overseer.exe`.

---

## Logging & Maintenance
- **Persistence:** Log files are stored in [/logs](file:///g:/SharedVM/Overseer/logs).
- **Cleanup:** The script automatically maintains the **oldest baseline log** and the **20 most recent logs**, purging intermediate data to save space.