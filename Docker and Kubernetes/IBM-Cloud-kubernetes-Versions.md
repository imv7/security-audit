# XX-D-NN Patch Management

#### Sampled Offering Component
- [ ] (add offering name)

#### Sampled Worker Nodes:
- [ ] (add worker nodes ids)

#### Sampled Patches:

- [ ] (add patch list, example: [USN-4336-1] GNU binutils vulnerabilities)

Please provide the following for the sampled worker nodes listed above:

1.	Use the `ibmcloud ks worker get` command list the details of the sampled worker nodes above. The output should include at least the following fields:
* Worker Node ID
* State
* Status
* Private VLAN
* Public VLAN
* Private IP
* Hardware
* Pool Name
* Pool ID
* Zone
* Flavor
* Version

2.	A screenshot of the ibmcloud CLI showing the complete ibmcloud command used to generate the output above.

3.	A PDF print out of the ‘Armada latest patch image archive’ where the package versions required to address the sampled patches listed above were first introduced for the OS version in question. The PDF should include at least the following fields:
* Image version
* Publish date
* Package name
* Package version
* Architecture
* Package description 

4.	A PDF print out of the Server record in SOS that includes the ‘Worker Image Version History’. Please ensure the Image version from the ‘Armada latest patch image archive’ provided above is visible in the PDF. If the specific Image version is not listed in the history (never applied or skipped), please make sure the nearest superseding applied image version is visible. The PDF should include at least the following fields:
* Worker Node name
* Cluster
* Worker Image Version History (Image version and Applied date)

5.	Any security exceptions (e.g. PCE) or risk evaluations (e.g. CDD) filed to postpone updating the vulnerable software package(s) for the sampled patches listed above beyond the due dates prescribed by the security policy.

6.	If any of the sampled patches listed above is not applicable for any reason, please provide irrefutable evidence to support that assertion (e.g. OS version not affected, vulnerable package not installed, etc.)
