package com.gzu.javawebproject.controller;

import com.gzu.javawebproject.dto.AssignmentCreateRequest;
import com.gzu.javawebproject.dto.AssignmentResponse;
import com.gzu.javawebproject.entity.Assignment;
import com.gzu.javawebproject.service.AssignmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/assignments")
public class AssignmentController {

    @Autowired
    private AssignmentService assignmentService;

    // 发布作业
    @PostMapping
    public String createAssignment(@RequestBody AssignmentCreateRequest request) {
        Assignment assignment = new Assignment();
        assignment.setCourseId(request.getCourseId());
        assignment.setTitle(request.getTitle());
        assignment.setDescription(request.getDescription());
        assignment.setDeadline(request.getDeadline());
        assignmentService.createAssignment(assignment);
        return "Assignment created successfully!";
    }

    // 获取某课程的所有作业
    @GetMapping("/{courseId}")
    public List<AssignmentResponse> getAssignmentsByCourseId(@PathVariable Long courseId) {
        return assignmentService.getAssignmentsByCourseId(courseId).stream().map(assignment -> {
            AssignmentResponse response = new AssignmentResponse();
            response.setId(assignment.getId());
            response.setTitle(assignment.getTitle());
            response.setDescription(assignment.getDescription());
            response.setDeadline(assignment.getDeadline());
            return response;
        }).collect(Collectors.toList());
    }
}
