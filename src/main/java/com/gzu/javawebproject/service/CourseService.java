package com.gzu.javawebproject.service;

import com.gzu.javawebproject.entity.Course;
import java.util.List;

public interface CourseService {
    Course createCourse(Course course);
    Course getCourseById(Long id);
    List<Course> getCoursesByTeacherId(Long teacherId);
    void updateCourse(Course course);
    void deleteCourse(Long id);
}
