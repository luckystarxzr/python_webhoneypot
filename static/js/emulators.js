// 通用提交处理函数
function handleEmulatorSubmit(formId, endpoint) {
    $(`#${formId}`).on('submit', function(e) {
        e.preventDefault();
        showLoading();

        $.ajax({
            url: endpoint,
            method: 'POST',
            data: $(this).serialize(),
            success: function(response) {
                showResult(response);
            },
            error: function(xhr) {
                showError(xhr.responseJSON?.message || '请求处理失败');
            }
        });
    });
}

// 显示加载状态
function showLoading() {
    $('#result').html(`
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">加载中...</span>
            </div>
        </div>
    `);
}

// 显示错误信息
function showError(message) {
    $('#result').html(`
        <div class="alert alert-danger">
            <strong>错误：</strong> ${escapeHtml(message)}
        </div>
    `);
}

// 隐藏加载状态:
function hideLoading() {
    $('.spinner-border').parent().remove();
}

// 显示结果
function showResult(response) {
    let resultHtml = `
        <div class="card ${getStatusClass(response.status)}">
            <div class="card-header d-flex justify-content-between align-items-center">
                <strong>${getStatusText(response.status)}</strong>
                <small>${response.timestamp || ''}</small>
            </div>
            <div class="card-body">
                ${formatDetails(response)}
            </div>
            ${response.status === 'blocked' ? getBlockedInfo(response) : ''}
        </div>
    `;

    $('#result').html(resultHtml);
}

// 获取状态对应的样式类
function getStatusClass(status) {
    switch(status) {
        case 'blocked':
            return 'border-danger';
        case 'ok':
            return 'border-success';
        default:
            return 'border-warning';
    }
}

// 获取状态文本
function getStatusText(status) {
    switch(status) {
        case 'blocked':
            return '攻击已被阻止';
        case 'ok':
            return '请求已通过';
        default:
            return '请求已记录';
    }
}

// 格式化详细信息
function formatDetails(response) {
    let details = '';

    // 处理命令注入结果
    if (response.output) {
        details += `
            <div class="mb-3">
                <h6 class="mb-2">命令输出:</h6>
                <pre class="bg-light p-2 rounded">${escapeHtml(response.output)}</pre>
            </div>`;
    }

    // 处理SQL注入结果
    if (response.query) {
        details += `
            <div class="mb-3">
                <h6 class="mb-2">SQL查询:</h6>
                <pre class="bg-light p-2 rounded">${escapeHtml(response.query)}</pre>
            </div>`;
    }

    // 处理XSS结果
    if (response.payload) {
        details += `
            <div class="mb-3">
                <h6 class="mb-2">XSS载荷:</h6>
                <pre class="bg-light p-2 rounded">${escapeHtml(response.payload)}</pre>
            </div>`;
    }

    // 处理文件包含结果
    if (response.file_content) {
        details += `
            <div class="mb-3">
                <h6 class="mb-2">文件内容:</h6>
                <pre class="bg-light p-2 rounded">${escapeHtml(response.file_content)}</pre>
            </div>`;
    }

    // 处理其他信息
    if (response.reason) {
        details += `
            <div class="alert alert-danger">
                <strong>拦截原因:</strong> ${escapeHtml(response.reason)}
            </div>`;
    }

    if (response.detected_pattern) {
        details += `
            <div class="alert alert-warning">
                <strong>检测到的模式:</strong> ${escapeHtml(response.detected_patterns.join(', '))}
            </div>`;
    }

    return details || '<p class="text-muted mb-0">无详细信息</p>';
}

// 获取被阻止的请求的额外信息
function getBlockedInfo(response) {
    return `
        <div class="card-footer bg-danger bg-opacity-10">
            <small class="text-danger">
                <i class="bi bi-shield-exclamation"></i>
                此请求已被WAF拦截并记录
            </small>
        </div>`;
}

// HTML转义函数
function escapeHtml(unsafe) {
    // 确保输入是字符串
    if (unsafe === null || unsafe === undefined) {
        return '';
    }
    
    // 转换为字符串
    unsafe = String(unsafe);
    
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// 初始化所有模拟器
document.addEventListener('DOMContentLoaded', function() {
    // 命令注入模拟器
    handleEmulatorSubmit('commandForm', '/api/emulators/command_injection');

    // CSRF模拟器
    handleEmulatorSubmit('csrfForm', '/api/emulators/csrf');

    // 目录遍历模拟器
    handleEmulatorSubmit('traversalForm', '/api/emulators/directory_traversal');

    // 文件包含模拟器
    handleEmulatorSubmit('inclusionForm', '/api/emulators/file_inclusion');

    // SQL注入模拟器
    handleEmulatorSubmit('sqlForm', '/api/emulators/sql_injection');

    // XSS模拟器
    handleEmulatorSubmit('xssForm', '/api/emulators/xss');
}); 