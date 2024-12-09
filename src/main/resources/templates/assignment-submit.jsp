<!DOCTYPE html>
<html>
<head>
    <title>提交作业</title>
</head>
<body>
<h1>提交作业</h1>
<form action="/api/submissions" method="post" enctype="multipart/form-data">
    <label for="assignmentId">选择作业:</label>
    <select id="assignmentId" name="assignmentId">
        <!-- 替换为动态加载的作业列表 -->
        <option value="201">作业1 - 数学</option>
        <option value="202">作业2 - 物理</option>
    </select>
    <br>
    <label for="content">提交内容:</label>
    <textarea id="content" name="content" required></textarea>
    <br>
    <label for="file">上传文件 (可选):</label>
    <input type="file" id="file" name="file">
    <input type="hidden" name="studentId" value="1001"> <!-- 替换为实际学生 ID -->
    <br>
    <button type="submit">提交作业</button>
</form>
</body>
</html>
