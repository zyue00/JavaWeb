package com.gzu.javawebproject.service.iml;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gzu.javawebproject.entity.Enrollment;
import com.gzu.javawebproject.mapper.EnrollmentMapper;
import com.gzu.javawebproject.service.EnrollmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EnrollmentServiceImpl implements EnrollmentService {
    @Autowired
    private EnrollmentMapper enrollmentMapper;

    @Override
    public void enrollStudent(Long studentId, Long courseId) {
        Enrollment enrollment = new Enrollment();
        enrollment.setStudentId(studentId);
        enrollment.setCourseId(courseId);
        enrollmentMapper.insert(enrollment);
    }

    @Override
    public List<Enrollment> getEnrollmentsByStudentId(Long studentId) {
        return enrollmentMapper.selectList(new QueryWrapper<Enrollment>().eq("student_id", studentId));
    }

    @Override
    public void dropCourse(Long enrollmentId) {
        enrollmentMapper.deleteById(enrollmentId);
    }
}
