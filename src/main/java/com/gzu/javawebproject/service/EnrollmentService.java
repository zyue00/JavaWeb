package com.gzu.javawebproject.service;

import com.gzu.javawebproject.entity.Enrollment;
import java.util.List;

public interface EnrollmentService {
    void enrollStudent(Long studentId, Long courseId);
    List<Enrollment> getEnrollmentsByStudentId(Long studentId);
    void dropCourse(Long enrollmentId);
}
