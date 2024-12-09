package com.gzu.javawebproject.dto;

import java.time.LocalDateTime;

public class EnrollmentResponse {
    private String courseName;
    private String teacherName;
    private LocalDateTime enrolledAt;

    // 手动创建 get 和 set 方法

    public String getCourseName() {
        return courseName;
    }

    public void setCourseName(String courseName) {
        this.courseName = courseName;
    }

    public String getTeacherName() {
        return teacherName;
    }

    public void setTeacherName(String teacherName) {
        this.teacherName = teacherName;
    }

    public LocalDateTime getEnrolledAt() {
        return enrolledAt;
    }

    public void setEnrolledAt(LocalDateTime enrolledAt) {
        this.enrolledAt = enrolledAt;
    }
}
