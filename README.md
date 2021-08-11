# Project

This repository is used to host the PowerShell install and upgrade helper script (install.ps1) for the modern, unified Microsoft Defender for Endpoint installer package for Windows Server 2012 R2 and Windows Server 2016. This script is not intended for use with Azure Defender, or with Microsoft Endpoint Configuration Manager version 2111 or later. For more information, please go to https://docs.microsoft.com/microsoft-365/security/defender-endpoint/server-migration?view=o365-worldwide.

SYNOPSIS  
Helper script for installing/uninstalling Microsoft Defender for Downlevel Servers.

DESCRIPTION  
On install scenario:
1. It removes the OMS workspace when the workspace ID is provided with the parameter RemoveMMA. **Note this step is for cleanup purposes only**.
2. The next step uninstalls SCEP if it is present.
3. Then, it checks for prerequisites and downloads and installs two hotfixes if the prerequisites have not been met. Note that on machines that have received recent  monthly update rollup packages, the prerequisites will have been met.
4. Next, it installs the Microsoft Defender for Downlevel Servers MSI (md4ws.msi downloaded from the onboarding page for Windows Server 2012 R2 and 2016). If the file is in the same directory as the script, no input is required.
5. Finally, it runs the onboarding script, if provided using the parameter OnboardingScript. Please use the script for Windows Server 2019 for **Group Policy** as it is non-interactive; the local onboarding script will fail.

On uninstall scenario:
1. It will run the offboarding script, if provided using the parameter OffboardingScript. Otherwise it is assumed that the machine is in an offboarded state. Please use the script for Windows Server 2019 for **Group Policy** as it is non-interactive; the local onboarding script will fail.
2. Uninstall the product.
3. Removes the Defender Powershell module, if it was loaded inside current Powershell session.

INPUTS  
    md4ws.msi
OUTPUTS  
    none  
**EXAMPLE 1**: Simply install the MSI. The script executes install steps 2, 3 and 4 mentioned above.  
```.\Install.ps1```  

**EXAMPLE 2**: Same as #1 except it will display the installer UI and enable more verbose logging for troubleshooting purposes.  
```.\Install.ps1 -UI -Log -Etl```  

**EXAMPLE 3**: Perform uninstall steps 2 and 3.  
```.\Install.ps1 -Uninstall```   

**EXAMPLE 4**: Same as example #3 except with additional logging.  
```.\Install.ps1 -Uninstall -Etl```  

**EXAMPLE 5**: Fully automate (including optional OMS workspace removal) installation and onboarding. In this case, the onboarding script is located in the same directory as the installer script and the installation package (MSI). Substitute <WORKSPACE_ID> with the ID found on the onboarding page (for Windows Server 2008 R2) in your tenant.  
```.\Install.ps1 -RemoveMMA <WORKSPACE_ID> -OnboardingScript ".\WindowsDefenderATPOnboardingScript.CMD"```  

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
