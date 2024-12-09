package com.gzu.javawebproject.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@TableName("assignment_submission")
public class Submission {
    @TableId
    private Long id;
    private Long assignmentId;
    private Long studentId;
    private String content;
    private LocalDateTime submittedAt;
    private Double grade;
    private String feedback;
}
