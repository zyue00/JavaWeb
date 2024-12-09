package com.gzu.javawebproject.controller;

import com.gzu.javawebproject.dto.CourseCreateRequest;
import com.gzu.javawebproject.dto.CourseResponse;
import com.gzu.javawebproject.entity.Course;
import com.gzu.javawebproject.service.CourseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/courses")
public class CourseController {
    @Autowired
    private CourseService courseService;

    // 创建课程
    @PostMapping
    public String createCourse(@RequestBody CourseCreateRequest request) {
        Course course = new Course();
        course.setName(request.getName());
        course.setDescription(request.getDescription());
        course.setTeacherId(request.getTeacherId());
        courseService.createCourse(course);
        return "Course created successfully!";
    }

    // 获取所有课程
    @GetMapping
    public List<CourseResponse> getAllCourses() {
        return courseService.getCoursesByTeacherId(null).stream().map(course -> {
            CourseResponse response = new CourseResponse();
            response.setId(course.getId());
            response.setName(course.getName());
            response.setDescription(course.getDescription());
            response.setTeacherName("Teacher ID: " + course.getTeacherId()); // 替换为真实的教师姓名
            return response;
        }).collect(Collectors.toList());
    }

    // 按课程ID获取课程详情
    @GetMapping("/{id}")
    public CourseResponse getCourseById(@PathVariable Long id) {
        Course course = courseService.getCourseById(id);
        CourseResponse response = new CourseResponse();
        response.setId(course.getId());
        response.setName(course.getName());
        response.setDescription(course.getDescription());
        response.setTeacherName("Teacher ID: " + course.getTeacherId()); // 替换为真实的教师姓名
        return response;
    }
}
