package com.gzu.javawebproject.dto;

import java.time.LocalDateTime;

public class AssignmentCreateRequest {
    private Long courseId;
    private String title;
    private String description;
    private LocalDateTime deadline;

    // 手动创建 get 和 set 方法

    public Long getCourseId() {
        return courseId;
    }

    public void setCourseId(Long courseId) {
        this.courseId = courseId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public LocalDateTime getDeadline() {
        return deadline;
    }

    public void setDeadline(LocalDateTime deadline) {
        this.deadline = deadline;
    }
}
