## TODO NEEDED TO KEEP ME ON TRACK

*[ ] Configure and setup android nanohttpd package build with component selection*  
- [X] Upgrade to Java 11, AGP 7.0.1, Gradel 7.0.2 and setup common.gradle to set optional build sdk configs.
- [X] Get a working AAR build for one of the sub projects modules.
- [X] Cleanup and make a clear separation of module/project dependencies and build specific dependencies.
- [X] Review options to upgrade to Java SDK 17 and realize multiple compile errors in the code hold this off.
- [X] Other cleanup and cherry-pick of commits available from the google source that are not available in master/upstream.
- [X] Review the Android.bp intended for AOSP system builds of nanohttpd for source sets to build app-scoped-private library
- [X] As part of getting a working AAR build reviewed the difference between AndroidLibrary and AndroidApplication build plugins
- [X] As part of getting a workking AAR build reviewed the plugin configurations and namespacing and app id's 
- [X] Cleanup multiple deprecation lint warnings, and cleared all deprecations for the Android AAR build
- [X] Identified the internal deprecations and reviewed the code to understand the correct use, and deprecations w/ java platform build can be ignored.
- [X] Identified and cleared other deprecations due to Gradle upgrade, and should be good to Gradle 8.9.
- [X] Identified the codebase is compatible with maximum of JDK 11, and AGP 7 is only AndroidGradlePlug version supporting, w/ max Gradle version of 7.0.2
- [X] Currently using a copy of the source directory, need to setup the sourceset to pattern match a source directory outside of it's own module directory.
- [X] Once source set works, move the module directory to root of project and enforce compilation with AAR 
- [X] Rollup justy the single AAR adding the other projects for core, websocket and webserver
- ~~[] Transform the Java Source Files Package Namespaces during compilation to prepend the package namespace and ensure no namespace collisions (Android)~~
- ~~[] Add something to the read me explaining what the Android build is why it is App Specific and not AOSP System and provide example run.~~
- ~~[] Set the source set to pull in and build all of the subprojects/modules into the android library, but make easy to comment out.~~
- [] Actually test it in an Android App once??? 
- [] Figure out why the libraries don't work, try the JAR files vs the AAR files vs the PKG files, get it working.
- [] Review the requirements for .java files to compile under JDK 17 without issues and start upgrading modules one by one.
- [] Since the project has both a Maven build and a gradle build, and maven is currently working, make sure Maven tags along for the ride.
- [] Since gradle is not generating the documentation use gradle exec task to trigger maven "generatMavenSite" to generate the docs.
- [] Add the Gradle Release plugin then align the release information in the Maven release files and Gradle, add the MavenPublish plugin to Gradle
- [] Test publishing to Maven with another simple library. Then publish. ( I think )
- [] Update the maven class docs to deploy to the github page instead, and setup a pre-release repository on github as well,
- [] Condition final release so it never runs without explicit change of the flags needed.
- [] Setup releases for the individual modules separately, under the jserver-libs group. So it looks like jserver-libs.nanohttpd and jserver-libs.jcifs
- [] Start working on putting any common utilities into there own library, and if they are "reused" make sure the license is directly on the source
- [] Rewrite similar libraries to be accommodating to what each project module is expecting, use overloaded constructors, and refactor.
- [] Release the jserver-libs.common to the main maven repository as soon as possible to reserve the name, and then use it.
- [] Gradle site generation docs via something like asciidoctor, jetbrains.dokka, or exec task in gradle task generateSite(type: Exec) {commandLine 'mvn', 'site'}
- [] The license-maven-plugin does not have a direct equivalent in Gradle - task enforceLicenses(type: Exec) {commandLine 'mvn', 'license:update-file-header'}
- [] Review and consider adding the pmd code quality analysis tool into the Gradle Build to keep alignment with the original maven build.
- [] Add spotbugs plugin in gradle for the alignment with the mvn build. I will do a check to make sure if any of those tasks don't run, we can leave it out.
*[ ]*  
*[ ]*  
*[ ]*  