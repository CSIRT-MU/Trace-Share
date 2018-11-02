<img src="https://is.muni.cz/www/325314/logo.png" width="50%"/>

The open platform for creation and sharing of network traffic traces.

&nbsp;

## About the project

Research validation and verification are fundamental principles of good scientific work. In terms of research in the area of network traffic measurement and analysis, however, these principles pose a great challenge. The research heavily depends not only on the correct processes of data usage but also on the availability of network traffic datasets that meet the common requirements and are publicly available. Without these datasets, we will never be able to reliably repeat, validate, and analyze research results.

The main idea of Trace-Share is based on annotated units of network traffic that can be synthetically generated, or derived from real-world traffic. These units typically contain only a minimum of personal data, so they can be shared and, thanks to the restrictions on the inclusion of interest-related traffic only, be easily annotated. They can be also easily normalized and combined with each other or with a real-world traffic to create semi-labeled datasets.

**Details and main ideas of the project are available in the publicly available publication [Towards Provable Network Traffic Measurement and Analysis via Semi-Labeled Trace Datasets](https://doi.org/10.23919/TMA.2018.8506498).**


## Getting started

The code in the repository is proof-of-concept implementation of basic ideas of the Trace-Share project. We are currently working on the web interface and tools, that will be easy to use by everyone. The results will appear in the repository soon. Stay tuned!

If you are interested in creation and normalization of network traces, check out the foolowing subprojects:
- [trace-creator](trace-creator) – virtual environment for the creation of packet traces
- [trace-analyzer](trace-analyzer) – script providing basic information about packet trace captures
- [trace-normalizer](trace-normalizer) - script facilitating normalization of packet trace capture
- [datasets](datasets) – an example of annotated units (will be deleted after web platform introduction)

## Cooperation

**Are you interested in research collaboration or want to contribute? Don't hesitate to contact us at [https://csirt.muni.cz](https://csirt.muni.cz/about-us/contact?lang=en)!**
