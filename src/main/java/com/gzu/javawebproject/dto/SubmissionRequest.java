package com.gzu.javawebproject.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class SubmissionRequest {
    private Long assignmentId;
    private Long studentId;
    private String content;
}
