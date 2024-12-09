package com.gzu.javawebproject.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gzu.javawebproject.entity.Submission;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface SubmissionMapper extends BaseMapper<Submission> {
    // 示例：按学生ID查询提交记录
    // List<Submission> findByStudentId(Long studentId);
}
