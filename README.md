# Project

This repository is used to host the PowerShell install and upgrade helper script (install.ps1) for the modern, unified Microsoft Defender for Endpoint installer package for Windows Server 2012 R2 and Windows Server 2016. For deployment and upgrades with Microsoft Defender for servers through Microsoft Defender for Cloud pleases reference https://docs.microsoft.com/en-us/azure/defender-for-cloud/integration-defender-for-endpoint?tabs=windows#enable-the-integration. For more information about other migration scenarios, please visit https://docs.microsoft.com/microsoft-365/security/defender-endpoint/server-migration?view=o365-worldwide.

Always use the latest available package, downloaded from the onboarding section of the Defender for Endpoint portal, for new installations. Some of the functionality contained in the script can depend on changes introduced in the package.

SYNOPSIS  
Helper script for installing/uninstalling Microsoft Defender for Downlevel Servers.

DESCRIPTION  
On install scenario:
1. It can remove the OMS workspace when the workspace ID is provided with the parameter **RemoveMMA**. **NOTE: this step is for cleanup purposes only**. ****When installing the new package, the previous sensor will stop running and the workspace is no longer used. You may however still need the MMA for other workspaces/functionality such as OMS, Log Analytics.  ****
2. The next step uninstalls SCEP - if it is present, and only on Windows Server 2012 R2 (on Windows Server 2016, SCEP is only a management component and is not required).
3. Then, it checks for prerequisites and downloads and installs two hotfixes on Windows Server 2012 R2 if the prerequisites have not been met (files are not found).
4. If Defender is not running on Windows Server 2016, it will attempt to activate it. If the feature is not installed, it attempts to enable the feature. If this requires a reboot, the script will stop; please reboot and run again to continue.
5. If Defender is installed and running but outdated, it updates to the latest platform version on Windows Server 2016 if required (NOTE: Defender must be in an upgradeable state, this requires at least one servicing stack and cumulative update to have been applied). If you have placed updateplatform.exe in the same directory, the script can use this in case the download location is not accessible.
6. Next, it installs the Microsoft Defender for Downlevel Servers MSI (md4ws.msi downloaded from the onboarding page for Windows Server 2012 R2 and 2016). If the file is in the same directory as the script, no input is required. If the product was already installed, it will attempt to perform a reinstallation with the provided MSI, but only if the machine is not in an onboarded state.
7. Finally, it runs the onboarding script, if provided using the parameter **OnboardingScript**. Please use the script for **Group Policy** as it is non-interactive; the local onboarding script will fail.

NOTE on machines that have received recent monthly update rollup packages, the prerequisites will have been met and most steps above will not be needed.

On uninstall scenario:
1. It will run the offboarding script, if provided using the parameter **OffboardingScript**. Otherwise it is assumed that the machine is in an offboarded state. **NOTE: Uninstallation is only possible if the machine has been offboarded first.** Please use the script for Windows Server 2019 for **Group Policy** as it is non-interactive; the local offboarding script will fail.
2. Uninstall the product.
3. Removes the Defender Powershell module, if it was loaded inside current Powershell session.

  
**EXAMPLE 1**: Install the MSI if it is present in the smae location as the script. The script executes install steps 2 through 6 mentioned above.  
```.\Install.ps1```  

**EXAMPLE 2**: Same as #1 except it will display the installer UI and disables verbose logging.  
```.\Install.ps1 -UI -NoMSILog -NoEtl```  

**EXAMPLE 3**: Same as #2 except it will set Defender Antivirus to not become the active antimalware immediately after installation to avoid interference with non-Microsoft antimalware solutions before onboarding. Make sure to set the "ForceDefenderPassiveMode" registry key on all servers where you wish to run protection capabilities in passive mode after onboarding. For more information on Passive mode, see [Need to set Microsoft Defender Antivirus to passive mode?](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-on-windows-server?#passive-mode-and-windows-server)

```.\Install.ps1 -UI -Passive```  

**EXAMPLE 4**: Perform uninstall steps 2 and 3.  
```.\Install.ps1 -Uninstall```   

**EXAMPLE 5**: Same as example #3 except with additional logging disabled.  
```.\Install.ps1 -Uninstall -NoMSILog -NoEtl```  

**EXAMPLE 6**: Fully automate (including optional OMS workspace removal) installation and onboarding. In this case, the onboarding script is located in the same directory as the installer script and the installation package (MSI). Substitute <WORKSPACE_ID> with the ID found on the onboarding page (for Windows Server 2008 R2) in your tenant.  
```.\Install.ps1 -RemoveMMA <WORKSPACE_ID> -OnboardingScript ".\WindowsDefenderATPOnboardingScript.CMD"```  

**EXAMPLE 7**: Offboard then uninstall the MSI.  
```.\Install.ps1 -Uninstall -OffboardingScript ".\WindowsDefenderATPOffboardingScript.CMD"```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
