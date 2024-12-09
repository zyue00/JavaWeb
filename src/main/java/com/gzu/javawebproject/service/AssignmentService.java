package com.gzu.javawebproject.service;

import com.gzu.javawebproject.entity.Assignment;
import java.util.List;

public interface AssignmentService {
    Assignment createAssignment(Assignment assignment);
    List<Assignment> getAssignmentsByCourseId(Long courseId);
    Assignment getAssignmentById(Long id);
    void deleteAssignment(Long id);
}
