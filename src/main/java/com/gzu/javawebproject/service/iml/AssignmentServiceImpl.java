package com.gzu.javawebproject.service.iml;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gzu.javawebproject.entity.Assignment;
import com.gzu.javawebproject.mapper.AssignmentMapper;
import com.gzu.javawebproject.service.AssignmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AssignmentServiceImpl implements AssignmentService {
    @Autowired
    private AssignmentMapper assignmentMapper;

    @Override
    public Assignment createAssignment(Assignment assignment) {
        assignmentMapper.insert(assignment);
        return assignment;
    }

    @Override
    public List<Assignment> getAssignmentsByCourseId(Long courseId) {
        return assignmentMapper.selectList(new QueryWrapper<Assignment>().eq("course_id", courseId));
    }

    @Override
    public Assignment getAssignmentById(Long id) {
        return assignmentMapper.selectById(id);
    }

    @Override
    public void deleteAssignment(Long id) {
        assignmentMapper.deleteById(id);
    }
}
