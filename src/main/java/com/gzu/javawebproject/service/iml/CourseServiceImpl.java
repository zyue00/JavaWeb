package com.gzu.javawebproject.service.iml;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gzu.javawebproject.entity.Course;
import com.gzu.javawebproject.mapper.CourseMapper;
import com.gzu.javawebproject.service.CourseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CourseServiceImpl implements CourseService {
    @Autowired
    private CourseMapper courseMapper;

    @Override
    public Course createCourse(Course course) {
        courseMapper.insert(course);
        return course;
    }

    @Override
    public Course getCourseById(Long id) {
        return courseMapper.selectById(id);
    }

    @Override
    public List<Course> getCoursesByTeacherId(Long teacherId) {
        return courseMapper.selectList(new QueryWrapper<Course>().eq("teacher_id", teacherId));
    }

    @Override
    public void updateCourse(Course course) {
        courseMapper.updateById(course);
    }

    @Override
    public void deleteCourse(Long id) {
        courseMapper.deleteById(id);
    }
}
