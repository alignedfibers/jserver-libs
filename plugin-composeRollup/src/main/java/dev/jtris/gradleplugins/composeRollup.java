package dev.jtris.gradleplugins;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

public class composeRollup implements Plugin<Project> {
    project.getTasks().register("composeDeliveryItems", task -> {

                task.setDescription("Wrapup modules for selective library inclusion, implementation, and alternative build plugin lifecylces ");
                task.doLast(t -> System.out.println("Hello World"));
            })
}