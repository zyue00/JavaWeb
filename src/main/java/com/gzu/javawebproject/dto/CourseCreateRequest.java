package com.gzu.javawebproject.dto;

public class CourseCreateRequest {
    private String name;
    private String description;
    private Long teacherId;

    // 手动创建 get 和 set 方法

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Long getTeacherId() {
        return teacherId;
    }

    public void setTeacherId(Long teacherId) {
        this.teacherId = teacherId;
    }
}
