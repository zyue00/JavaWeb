package com.gzu.javawebproject.controller;

import com.gzu.javawebproject.dto.EnrollmentRequest;
import com.gzu.javawebproject.dto.EnrollmentResponse;
import com.gzu.javawebproject.entity.Enrollment;
import com.gzu.javawebproject.service.EnrollmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/enrollments")
public class EnrollmentController {
    @Autowired
    private EnrollmentService enrollmentService;

    // 学生选课
    @PostMapping
    public String enrollStudent(@RequestBody EnrollmentRequest request) {
        enrollmentService.enrollStudent(request.getStudentId(), request.getCourseId());
        return "Enrollment successful!";
    }

    // 获取学生的选课记录
    @GetMapping("/{studentId}")
    public List<EnrollmentResponse> getEnrollmentsByStudentId(@PathVariable Long studentId) {
        return enrollmentService.getEnrollmentsByStudentId(studentId).stream().map(enrollment -> {
            EnrollmentResponse response = new EnrollmentResponse();
            response.setCourseName("Course ID: " + enrollment.getCourseId()); // 替换为真实课程名称
            response.setTeacherName("Teacher Info Placeholder"); // 替换为真实教师信息
            response.setEnrolledAt(enrollment.getEnrolledAt());
            return response;
        }).collect(Collectors.toList());
    }
}
