package com.gzu.javawebproject.dto;

public class EnrollmentRequest {
    private Long courseId;
    private Long studentId;

    // 手动创建 get 和 set 方法

    public Long getCourseId() {
        return courseId;
    }

    public void setCourseId(Long courseId) {
        this.courseId = courseId;
    }

    public Long getStudentId() {
        return studentId;
    }

    public void setStudentId(Long studentId) {
        this.studentId = studentId;
    }
}
