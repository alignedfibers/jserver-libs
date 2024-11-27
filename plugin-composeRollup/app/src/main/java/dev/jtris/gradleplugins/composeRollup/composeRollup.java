package dev.jtris.gradleplugins.composeRollup;

//import org.gradle.internal.impldep.org.junit.Test;
import org.gradle.testkit.runner.GradleRunner;
import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.TaskOutcome;
import org.testng.annotations.Test;
import java.io.File;
import java.nio.file.Files;
import static org.junit.jupiter.api.Assertions.*;

public class composeRollup {
    @Test
    void ComposeRollup() throws Exception {
        // Setup mock project directory
        File projectDir = Files.createTempDirectory("mock-project").toFile();
        Files.writeString(new File(projectDir, "settings.gradle").toPath(), "");
        Files.writeString(new File(projectDir, "build.gradle").toPath(),
                "plugins { id 'com.example.myplugin' }");

        // Run Gradle build using TestKit
        BuildResult result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath() // Use plugin JARs on classpath
                .withArguments("hello") // Target task
                .build();

        // Assert expected output
        assertTrue(result.getOutput().contains("Hello from MyPlugin!"));
        assertEquals(TaskOutcome.SUCCESS, result.task(":hello").getOutcome());
    }
}