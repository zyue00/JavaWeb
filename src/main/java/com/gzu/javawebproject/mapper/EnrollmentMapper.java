package com.gzu.javawebproject.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gzu.javawebproject.entity.Enrollment;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface EnrollmentMapper extends BaseMapper<Enrollment> {
    // 示例：按学生ID查询所有选课记录
    // List<Enrollment> findByStudentId(Long studentId);
}
