package com.gzu.javawebproject.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Data
@Getter
@Setter
public class SubmissionResponse {
    private String assignmentTitle;
    private String studentName;
    private LocalDateTime submittedAt;
    private Double grade;
    private String feedback;
}
