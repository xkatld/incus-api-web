let captchaAnswer = 0;

function generateCaptcha() {
    const num1 = Math.ceil(Math.random() * 9) + 1;
    const num2 = Math.ceil(Math.random() * 9) + 1;
    captchaAnswer = num1 + num2;
    const captchaQuestionEl = document.getElementById('captchaQuestion');
    if (captchaQuestionEl) {
        captchaQuestionEl.innerText = `${num1} + ${num2} = ?`;
    }
    const captchaInputEl = document.getElementById('captchaInput');
    if (captchaInputEl) {
        captchaInputEl.value = '';
    }
}

document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('loginForm')) {
        generateCaptcha();
        const refreshButton = document.getElementById('refreshCaptchaBtn');
        if(refreshButton) {
            refreshButton.addEventListener('click', generateCaptcha);
        }

        const loginForm = document.getElementById('loginForm');
        loginForm.addEventListener('submit', function(event) {
            const userAnswer = parseInt(document.getElementById('captchaInput').value, 10);
            if (userAnswer !== captchaAnswer) {
                event.preventDefault();
                showToast('验证码错误，请重试。', 'danger');
                generateCaptcha();
            }
        });
    }
});


function showToast(message, type = 'info') {
    let toastType = 'info';
    if (type === 'success') {
        toastType = 'success';
    } else if (type === 'error') {
        toastType = 'danger';
    } else if (type === 'warning') {
        toastType = 'warning';
    }
    const toastContainer = $('#toastContainer');
    const toastHtml = `
        <div class="toast align-items-center text-bg-${toastType} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;
    const toastElement = $(toastHtml);
    toastContainer.append(toastElement);
    const toast = new bootstrap.Toast(toastElement[0]);
    toast.show();
    toastElement.on('hidden.bs.toast', function () {
        $(this).remove();
    });
}

function setButtonProcessing(button, isProcessing) {
    const $button = $(button);
    if (!$button.length) {
        return;
    }
    if (isProcessing) {
        if (!$button.data('original-html')) {
            $button.data('original-html', $button.html());
            const originalText = $button.text().trim();
            const spinnerHtml = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
            $button.html(spinnerHtml + (originalText ? ' 处理中...' : ''));
            $button.addClass('btn-processing').prop('disabled', true);
        }
    } else {
        if ($button.data('original-html')) {
             $button.html($button.data('original-html'));
             $button.data('original-html', null);
             $button.removeClass('btn-processing').prop('disabled', false);
        } else {
             $button.removeClass('btn-processing').prop('disabled', false);
        }
    }
}

let currentConfirmAction = null;
let currentConfirmContainerName = null;
let currentConfirmRuleId = null;
let currentConfirmButtonElement = null;

function showConfirmationModal(actionType, nameOrId, buttonElement) {
    currentConfirmAction = actionType;
    currentConfirmButtonElement = buttonElement;
    const modalTitle = $('#confirmModalLabel');
    const modalBody = $('#confirmModalBody');
    const confirmButton = $('#confirmActionButton');
    let message = '';
    let buttonClass = 'btn-primary';
    let buttonText = '确认';

    if (actionType === 'start_container') {
        currentConfirmContainerName = nameOrId;
        currentConfirmRuleId = null;
        modalTitle.text('确认启动');
        message = `确定要启动容器 <strong>${nameOrId}</strong> 吗？`;
        buttonClass = 'btn-success';
        buttonText = '启动';
    } else if (actionType === 'stop_container') {
        currentConfirmContainerName = nameOrId;
        currentConfirmRuleId = null;
        modalTitle.text('确认停止');
        message = `确定要停止容器 <strong>${nameOrId}</strong> 吗？`;
        buttonClass = 'btn-warning';
        buttonText = '停止';
    } else if (actionType === 'restart_container') {
        currentConfirmContainerName = nameOrId;
        currentConfirmRuleId = null;
        modalTitle.text('确认重启');
        message = `确定要重启容器 <strong>${nameOrId}</strong> 吗？`;
        buttonClass = 'btn-warning';
        buttonText = '重启';
    } else if (actionType === 'delete_container') {
        currentConfirmContainerName = nameOrId;
         currentConfirmRuleId = null;
        modalTitle.text('确认删除容器');
        message = `<strong>警告：</strong> 这将永久删除容器 <strong>${nameOrId}</strong> 及其所有数据！<br>同时将强制删除所有通过本应用添加的关联 NAT 规则。<br>确定删除吗？`;
        buttonClass = 'btn-danger';
        buttonText = '删除容器';
     } else if (actionType === 'delete_nat_rule') {
         currentConfirmContainerName = null;
         currentConfirmRuleId = nameOrId;
        modalTitle.text('确认删除 NAT 规则');
        message = `确定要删除 ID 为 <strong>${nameOrId}</strong> 的 NAT 规则吗？此操作将尝试移除对应的 iptables 规则记录 (仅针对通过本应用添加的规则)。`;
        buttonClass = 'btn-danger';
        buttonText = '删除规则';
    }
    modalBody.html(message);
    confirmButton.removeClass('btn-primary btn-warning btn-danger btn-success').addClass(buttonClass).text(buttonText);
    setButtonProcessing(confirmButton, false);
    const confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));
    confirmModal.show();
}

$('#confirmActionButton').click(function() {
    const actionType = currentConfirmAction;
    const buttonElement = currentConfirmButtonElement;
    const confirmButton = $(this);
    if (!actionType || !buttonElement) {
        showToast("确认信息丢失，无法执行操作。", 'danger');
        const confirmModal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
        if (confirmModal) confirmModal.hide();
        return;
    }
    setButtonProcessing(confirmButton, true);
     if (actionType !== 'delete_nat_rule') {
         setButtonProcessing(buttonElement, true);
     }
    if (actionType === 'delete_nat_rule') {
        const ruleId = currentConfirmRuleId;
        $.ajax({
            url: `/container/nat_rule/${ruleId}`,
            type: 'DELETE',
            success: function(data) {
                showToast(data.message, data.status);
                if (data.status === 'success' || data.status === 'warning') {
                    const containerNameInModalLabel = $('#infoModalLabel').text().replace('容器信息: ', '');
                    if (containerNameInModalLabel) {
                        loadNatRules(containerNameInModalLabel);
                    } else {
                         setTimeout(() => location.reload(), 1000);
                    }
                }
            },
            error: function(jqXHR) {
                if (jqXHR.status === 401) {
                    showToast("操作需要认证，请重新登录。", 'danger');
                    setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
                } else {
                    const message = jqXHR.responseJSON ? (jqXHR.responseJSON.message || "未知错误") : `删除 NAT 规则请求失败。`;
                    showToast("操作失败: " + message, 'danger');
                }
            },
            complete: function() {
                const confirmModal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
                if (confirmModal) confirmModal.hide();
                setButtonProcessing(buttonElement, false);
                setButtonProcessing(confirmButton, false);
            }
        });
    } else {
        const containerName = currentConfirmContainerName;
        let action = actionType.replace('_container', '');
        $.post(`/container/${containerName}/action`, { action: action }, function(data) {
            showToast(data.message, data.status);
            if (data.status === 'success') {
                 setTimeout(() => location.reload(), 1000);
            }
        }).fail(function(jqXHR) {
             if (jqXHR.status === 401) {
                showToast("操作需要认证，请重新登录。", 'danger');
                setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
             } else {
                const message = jqXHR.responseJSON ? (jqXHR.responseJSON.message || "未知错误") : `执行 ${action} 操作请求失败。`;
                showToast("操作失败: " + message, 'danger');
                setButtonProcessing(buttonElement, false);
             }
        }).always(function() {
            const confirmModal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
            if (confirmModal) confirmModal.hide();
             setButtonProcessing(confirmButton, false);
        });
    }
});

$('#confirmModal').on('hidden.bs.modal', function () {
    currentConfirmAction = null;
    currentConfirmContainerName = null;
    currentConfirmRuleId = null;
});

function handleCreateContainerFormSubmit(event) {
    event.preventDefault();
    const form = $(this);
    const submitButton = form.find('button[type="submit"]');
    setButtonProcessing(submitButton, true);
    var formData = form.serialize();
    $.ajax({
        url: "/container/create",
        type: "POST",
        data: formData,
        success: function(data) {
            showToast(data.message, data.status);
            if (data.status === 'success') {
                form[0].reset();
                if (form.attr('id') === 'createContainerFormMobile') {
                    const modal = bootstrap.Modal.getInstance(document.getElementById('createContainerModalMobile'));
                    if (modal) modal.hide();
                }
                setTimeout(() => location.reload(), 1000);
            }
        },
        error: function(jqXHR) {
             if (jqXHR.status === 401) {
                showToast("操作需要认证，请重新登录。", 'danger');
                setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
             } else {
                const message = jqXHR.responseJSON ? jqXHR.responseJSON.message : "创建容器请求失败。";
                showToast("错误: " + message, 'danger');
             }
        },
        complete: function() {
            setButtonProcessing(submitButton, false);
        }
    });
}

$('#createContainerForm').submit(handleCreateContainerFormSubmit);
$('#createContainerFormMobile').submit(handleCreateContainerFormSubmit);


function performAction(containerName, action, buttonElement) {
    if (action === 'restart') {
        showConfirmationModal('restart_container', containerName, buttonElement);
    } else if (action === 'delete') {
        showConfirmationModal('delete_container', containerName, buttonElement);
    } else if (action === 'start') {
        showConfirmationModal('start_container', containerName, buttonElement);
    } else if (action === 'stop') {
        showConfirmationModal('stop_container', containerName, buttonElement);
    }
}

function showInfo(containerName, buttonElement) {
    const basicInfoContent = $('#basicInfoContent');
    const natRulesListContainer = $('#natRulesList');
    const natRulesContent = $('#natRulesContent');
    const natRulesError = $('#natRulesError');
    const infoError = $('#infoError');
    const infoModal = new bootstrap.Modal(document.getElementById('infoModal'));
    $('#infoModalLabel').text(`容器信息: ${containerName}`);
    basicInfoContent.html('正在加载基础信息...');
    natRulesContent.html('<li>正在加载 NAT 规则...</li>');
    natRulesError.addClass('d-none').text('');
     infoError.addClass('d-none').text('');
    natRulesListContainer.show();
    setButtonProcessing(buttonElement, true);
    $.ajax({
        url: `/container/${containerName}/info`,
        type: "GET",
        success: function(data) {
             if (data.status === 'NotFound') {
                 basicInfoContent.html(`<strong>错误:</strong> ${data.message}`);
                 infoError.removeClass('d-none').text(data.message);
                 showToast("加载容器信息失败。", 'danger');
                 natRulesListContainer.hide();
                 return;
             }

            let limitsHtml = '<h6>资源限制:</h6><ul class="list-unstyled">';
            let hasLimits = false;
            if (data.config && data.config['limits.cpu']) {
                limitsHtml += `<li><strong>CPU 核心数:</strong> ${data.config['limits.cpu']}</li>`;
                hasLimits = true;
            }
            if (data.config && data.config['limits.cpu.allowance']) {
                limitsHtml += `<li><strong>CPU 占用率:</strong> ${data.config['limits.cpu.allowance']}</li>`;
                hasLimits = true;
            }
             if (data.config && data.config['limits.memory']) {
                limitsHtml += `<li><strong>内存:</strong> ${data.config['limits.memory']}</li>`;
                hasLimits = true;
            }
             if (data.config && data.config['limits.memory.swap']) {
                limitsHtml += `<li><strong>启用 Swap:</strong> ${data.config['limits.memory.swap']}</li>`;
                hasLimits = true;
            }
            if (data.config && data.config['security.nesting']) {
                limitsHtml += `<li><strong>允许嵌套:</strong> ${data.config['security.nesting']}</li>`;
                hasLimits = true;
            }
            let rootDiskSize = '默认';
            if(data.devices && data.devices.root && data.devices.root.size) {
                 rootDiskSize = data.devices.root.size;
                 hasLimits = true;
            }
            limitsHtml += `<li><strong>硬盘 (root):</strong> ${rootDiskSize}</li>`;

            if (!hasLimits && rootDiskSize === '默认') {
                 limitsHtml += '<li>未设置特定资源限制。</li>';
            }
            limitsHtml += '</ul><hr>';


            let infoHtml = `
                <p><strong>名称:</strong> ${data.name}</p>
                <p><strong>状态:</strong> <span class="badge bg-${data.status === 'Running' ? 'success' : data.status === 'Stopped' ? 'danger' : 'secondary'}">${data.status}</span> (代码: ${data.status_code})</p>
                <p><strong>IP 地址:</strong> ${data.ip && data.ip !== 'N/A' ? data.ip : '-'}</p>
                <p><strong>镜像来源/描述:</strong> ${data.description && data.description !== 'N/A' ? data.description : data.image_source && data.image_source !== 'N/A' ? data.image_source : 'N/A'}</p>
                <p><strong>创建时间:</strong> ${data.created_at ? data.created_at.split('T')[0] : 'N/A'}</p>
                <p><strong>架构:</strong> ${data.architecture && data.architecture !== 'N/A' ? data.architecture : 'N/A'}</p>
                <p><strong>类型:</strong> ${data.type}</p>
                 <p><strong>临时容器:</strong> ${data.ephemeral ? '是' : '否'}</p>
                <p><strong>配置文件:</strong> ${data.profiles.join(', ') || '无'}</p>
                ${limitsHtml}
                 <p><small>${data.message}</small></p>
            `;
            basicInfoContent.html(infoHtml);
            if (!data.live_data_available && data.status !== 'NotFound') {
                 showToast(data.message, 'warning');
            }
            loadNatRules(containerName);
        },
        error: function(jqXHR) {
             if (jqXHR.status === 401) {
                showToast("操作需要认证，请重新登录。", 'danger');
                setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
             } else {
                const message = jqXHR.responseJSON ? jqXHR.responseJSON.message : "请求失败，无法加载详细信息。";
                basicInfoContent.html(`<strong>错误:</strong> ${message}`);
                infoError.removeClass('d-none').text(message);
                natRulesContent.html('<li>无法加载 NAT 规则。</li>');
                natRulesListContainer.hide();
                showToast("加载容器信息失败。", 'danger');
             }
        },
        complete: function() {
            setButtonProcessing(buttonElement, false);
            infoModal.show();
        }
    });
}

function loadNatRules(containerName) {
    const natRulesContent = $('#natRulesContent');
     const natRulesError = $('#natRulesError');
    natRulesContent.html('<li>正在加载 NAT 规则...</li>');
    natRulesError.addClass('d-none').text('');
     $.ajax({
        url: `/container/${containerName}/nat_rules`,
        type: "GET",
        success: function(data) {
            natRulesContent.empty();
            if (data.status === 'success' && data.rules && data.rules.length > 0) {
                data.rules.forEach(rule => {
                    const ruleHtml = `
                        <li data-rule-id="${rule.id}">
                            <span class="rule-details">
                                <strong>ID ${rule.id}:</strong> 主机 ${rule.host_port}/${rule.protocol} → 容器 ${rule.ip_at_creation}:${rule.container_port}
                                <br><small class="text-muted">记录创建时间: ${rule.created_at ? new Date(rule.created_at).toLocaleString() : 'N/A'}</small>
                            </span>
                            <span class="rule-actions">
                                 <button class="btn btn-sm btn-danger" onclick="deleteNatRule(${rule.id}, this)">删除</button>
                            </span>
                        </li>
                    `;
                    natRulesContent.append(ruleHtml);
                });
            } else if (data.status === 'success' && data.rules && data.rules.length === 0) {
                natRulesContent.html('<li>没有通过本应用添加的 NAT 规则记录。</li>');
            } else {
                 natRulesContent.html('<li>加载 NAT 规则失败。</li>');
                 natRulesError.removeClass('d-none').text(data.message || '未知错误获取规则列表。');
                 showToast(data.message || "加载 NAT 规则失败。", 'danger');
            }
        },
        error: function(jqXHR) {
             if (jqXHR.status === 401) {
                showToast("加载 NAT 规则需要认证，请重新登录。", 'danger');
                setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
             } else {
                 const message = jqXHR.responseJSON ? jqXHR.responseJSON.message : "请求失败，无法加载 NAT 规则。";
                 natRulesContent.html('<li>加载 NAT 规则失败。</li>');
                 natRulesError.removeClass('d-none').text(message);
                 showToast(message, 'danger');
             }
        }
    });
}

function deleteNatRule(ruleId, buttonElement) {
    showConfirmationModal('delete_nat_rule', ruleId, buttonElement);
}

function openExecModal(containerName) {
    $('#execContainerName').val(containerName);
    $('#execModalLabel').text(`在 ${containerName} 内执行命令`);
    $('#commandInput').val('');
    $('#execOutput').text('');
    $('#execOutput').removeClass('success error');
    setButtonProcessing($('#execButton'), false);
    loadQuickCommands(true);
    var execModal = new bootstrap.Modal(document.getElementById('execModal'));
    execModal.show();
}

$('#execCommandForm').submit(function(event) {
    event.preventDefault();
    const form = $(this);
    const submitButton = $('#execButton', form);
    const outputArea = $('#execOutput');
    var containerName = $('#execContainerName').val();
    var command = $('#commandInput').val(); // Reads from textarea
    if (!command.trim()) {
        showToast("请输入要执行的命令。", 'warning');
        return;
    }
    outputArea.text('正在执行...');
    outputArea.removeClass('success error');
    setButtonProcessing(submitButton, true);
    $.ajax({
        url: `/container/${containerName}/exec`,
        type: "POST",
        data: { command: command },
        success: function(data) {
            if (data.status === 'success') {
                outputArea.text(data.output);
                outputArea.addClass('success');
                showToast("命令执行成功。", 'success');
            } else {
                outputArea.text('命令执行失败:\n' + (data.output || data.message || '无详细输出'));
                outputArea.addClass('error');
                showToast(data.message || "命令执行失败。", 'danger');
            }
        },
        error: function(jqXHR) {
             if (jqXHR.status === 401) {
                showToast("操作需要认证，请重新登录。", 'danger');
                setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
             } else {
                const message = jqXHR.responseJSON ? (jqXHR.responseJSON.output || jqXHR.responseJSON.message || '未知错误') : "执行命令请求失败。";
                outputArea.text("请求失败:\n" + message);
                outputArea.addClass('error');
                showToast("请求失败。", 'danger');
             }
        },
        complete: function() {
            setButtonProcessing(submitButton, false);
        }
    });
});

$('#useQuickCommandBtn').click(function() {
    const selectedCommand = $('#quickCommandSelect').val();
    if (selectedCommand) {
        $('#commandInput').val(selectedCommand); // Sets textarea value
    }
});


function openNatModal(containerName) {
    $('#natContainerName').val(containerName);
    $('#natModalLabel').text(`为容器 ${containerName} 添加 NAT 规则`);
    $('#hostPort').val('');
    $('#containerPort').val('');
    $('#protocol').val('tcp');
    $('#natContainerIP').val('正在获取 IP...');
    setButtonProcessing($('#addNatButton'), false);
    var natModal = new bootstrap.Modal(document.getElementById('natModal'));
    natModal.show();
    $.ajax({
        url: `/container/${containerName}/info`,
        type: "GET",
        success: function(data) {
             if (data.status === 'NotFound' || data.status !== 'Running' || !data.ip || data.ip === 'N/A') {
                 const ipError = data.message || "无法获取容器 IP 地址或容器未运行。";
                 $('#natContainerIP').val('获取 IP 失败: ' + (data.ip && data.ip === 'N/A' ? '未分配 IP' : data.status !== 'Running' ? '容器未运行' : ipError));
                 $('#addNatButton').prop('disabled', true).text('无法添加 (无IP)');
                 showToast("无法添加 NAT 规则: " + (data.status !== 'Running' ? '容器未运行' : '无法获取IP'), 'warning');
             } else {
                $('#natContainerIP').val(data.ip);
                $('#addNatButton').prop('disabled', false).text('添加规则');
             }
        },
        error: function(jqXHR) {
             if (jqXHR.status === 401) {
                 showToast("获取容器信息需要认证，请重新登录。", 'danger');
                 var natModalInstance = bootstrap.Modal.getInstance(document.getElementById('natModal'));
                 if (natModalInstance) natModalInstance.hide();
                 setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
             } else {
                 $('#natContainerIP').val('获取 IP 失败');
                 $('#addNatButton').prop('disabled', true).text('无法添加 (无IP)');
                 const message = jqXHR.responseJSON ? jqXHR.responseJSON.message : "获取容器 IP 地址失败。";
                 showToast(message, 'danger');
             }
        }
    });
}

$('#addNatForm').submit(function(event) {
    event.preventDefault();
    const form = $(this);
    const submitButton = $('#addNatButton', form);
    const containerName = $('#natContainerName').val();
    const hostPort = $('#hostPort').val();
    const containerPort = $('#containerPort').val();
    const protocol = $('#protocol').val();
    if (!hostPort || !containerPort || !protocol) {
        showToast("请填写所有 NAT 规则信息。", 'warning');
        return;
    }
    setButtonProcessing(submitButton, true);
    $.ajax({
        url: `/container/${containerName}/add_nat_rule`,
        type: "POST",
        data: {
            host_port: hostPort,
            container_port: containerPort,
            protocol: protocol
        },
        success: function(data) {
            showToast(data.message, data.status);
            if (data.status === 'success' || data.status === 'warning') {
                 const containerNameInInfoModal = $('#infoModalLabel').text().replace('容器信息: ', '');
                 if (containerNameInInfoModal === containerName) {
                     loadNatRules(containerName);
                 }
                 if (data.status === 'success') {
                     $('#hostPort').val('');
                     $('#containerPort').val('');
                     $('#protocol').val('tcp');
                 }
            }
        },
        error: function(jqXHR) {
            if (jqXHR.status === 401) {
                 showToast("操作需要认证，请重新登录。", 'danger');
                 var natModalInstance = bootstrap.Modal.getInstance(document.getElementById('natModal'));
                 if (natModalInstance) natModalInstance.hide();
                 setTimeout(() => window.location.href = "/login?next=" + window.location.pathname, 1000);
             } else {
                const message = jqXHR.responseJSON ? (jqXHR.responseJSON.output || jqXHR.responseJSON.message || '未知错误') : "添加 NAT 规则请求失败。";
                showToast(message, 'danger');
             }
        },
        complete: function() {
            setButtonProcessing(submitButton, false);
        }
    });
});

let term;
let fitAddon;
let socket;

function openSshModal(containerName) {
    $('#sshModalLabel').text(`在线 SSH: ${containerName}`);
    const sshModalEl = document.getElementById('sshModal');
    const sshModal = new bootstrap.Modal(sshModalEl);

    sshModalEl.addEventListener('shown.bs.modal', function () {
        $.get(`/container/${containerName}/info`, function(data) {
            if (data.ip && data.ip !== 'N/A' && data.status === 'Running') {
                initializeTerminal(containerName, data.ip);
            } else {
                $('#terminal').html('<div class="alert alert-danger p-3 m-3">无法获取容器IP地址或容器未运行，无法启动SSH。</div>');
            }
        }).fail(function() {
             $('#terminal').html('<div class="alert alert-danger p-3 m-3">获取容器信息失败，无法启动SSH。</div>');
        });
    }, { once: true });

    sshModal.show();
}

function initializeTerminal(containerName, ip) {
    const terminalContainer = document.getElementById('terminal');
    terminalContainer.innerHTML = '';

    term = new Terminal({ cursorBlink: true, rows: 25, cols: 80, theme: { background: '#000000'} });
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalContainer);
    fitAddon.fit();
    term.focus();

    term.writeln('正在连接到服务器...');

    socket = io();

    socket.on('connect', () => {
        term.writeln('✅ 连接成功，正在启动SSH会话...');
        socket.emit('start_ssh', { 'container': containerName, 'ip': ip, 'cols': term.cols, 'rows': term.rows });
    });

    socket.on('ssh_output', (data) => {
        term.write(data);
    });

    socket.on('disconnect', () => {
        term.writeln('\r\n❌ 与服务器断开连接。');
        if(socket) socket.disconnect();
    });

    socket.on('ssh_error', (message) => {
        term.writeln(`\r\n❌ SSH 错误: ${message}`);
        if(socket) socket.disconnect();
    });

    term.onData((data) => {
        if(socket && socket.connected) {
            socket.emit('ssh_input', { 'input': data });
        }
    });

     $(window).on('resize.ssh', function() {
        if(fitAddon && term) {
            fitAddon.fit();
            if (socket && socket.connected) {
                socket.emit('ssh_resize', { 'cols': term.cols, 'rows': term.rows });
            }
        }
     });

     $('#sshModal').on('shown.bs.modal.ssh', function () {
         if(fitAddon && term) {
             fitAddon.fit();
             term.focus();
         }
     });
}

$('#sshModal').on('hidden.bs.modal', function () {
    if (socket) {
        socket.disconnect();
        socket = null;
    }
    if (term) {
        term.dispose();
        term = null;
    }
    $('#terminal').html('');
    $(window).off('resize.ssh');
    $('#sshModal').off('shown.bs.modal.ssh');
});


$('#infoModal').on('hidden.bs.modal', function () {
  $('#basicInfoContent').html('正在加载基础信息...');
  $('#natRulesContent').html('<li>正在加载 NAT 规则...</li>');
  $('#natRulesError').addClass('d-none').text('');
  $('#infoError').addClass('d-none').text('');
  $('#infoModalLabel').text('容器信息');
   $('#natRulesList').hide();
});

$('#execModal').on('hidden.bs.modal', function () {
  $('#execContainerName').val('');
  $('#commandInput').val('');
  $('#execOutput').text('');
  $('#execOutput').removeClass('success error');
  $('#execModalLabel').text('在容器内执行命令');
  $('#quickCommandSelect').html('<option value="" selected>-- 选择或手动输入 --</option>');
  setButtonProcessing($('#execButton'), false);
});

$('#natModal').on('hidden.bs.modal', function () {
    $('#natContainerName').val('');
    $('#natContainerIP').val('');
    $('#hostPort').val('');
    $('#containerPort').val('');
    $('#protocol').val('tcp');
    $('#natModalLabel').text('为容器添加 NAT 规则');
    setButtonProcessing($('#addNatButton'), false);
    $('#addNatButton').prop('disabled', false).text('添加规则');
});

function loadQuickCommands(populateSelect = false) {
    const list = $('#quickCommandsList');
    const select = $('#quickCommandSelect');
    list.html('<li class="list-group-item">正在加载...</li>');
    if (populateSelect) {
        select.html('<option value="" selected>-- 正在加载 --</option>');
    }

    $.ajax({
        url: "/quick_commands",
        type: "GET",
        success: function(data) {
            list.empty();
            if (populateSelect) {
                select.html('<option value="" selected>-- 选择或手动输入 --</option>');
            }

            if (data.status === 'success' && data.commands && data.commands.length > 0) {
                data.commands.forEach(cmd => {
                    // Make command preview safer for HTML and shorter
                    const safeCommandPreview = cmd.command.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    const shortPreview = safeCommandPreview.split('\n')[0].substring(0, 50) + (cmd.command.length > 50 || cmd.command.includes('\n') ? '...' : '');

                    const listItem = `
                        <li class="list-group-item d-flex justify-content-between align-items-center" data-command-id="${cmd.id}">
                            <span><strong>${cmd.name}:</strong> <code>${shortPreview}</code></span>
                            <button class="btn btn-sm btn-danger" onclick="deleteQuickCommand(${cmd.id}, this)">删除</button>
                        </li>`;
                    list.append(listItem);
                    if (populateSelect) {
                         // Use the full command in the value attribute
                         const optionItem = `<option value="${cmd.command.replace(/"/g, '&quot;')}">${cmd.name}</option>`;
                         select.append(optionItem);
                    }
                });
            } else if (data.status === 'success') {
                list.html('<li class="list-group-item">还没有快捷命令。</li>');
                 if (populateSelect) {
                    select.html('<option value="" selected>-- 没有快捷命令 --</option>');
                 }
            } else {
                list.html('<li class="list-group-item text-danger">加载失败。</li>');
                 if (populateSelect) {
                    select.html('<option value="" selected>-- 加载失败 --</option>');
                 }
                showToast("加载快捷命令失败: " + (data.message || '未知错误'), 'danger');
            }
        },
        error: function(jqXHR) {
            list.html('<li class="list-group-item text-danger">加载失败。</li>');
             if (populateSelect) {
                select.html('<option value="" selected>-- 加载失败 --</option>');
             }
            showToast("加载快捷命令请求失败。", 'danger');
        }
    });
}

function addQuickCommand(event) {
    event.preventDefault();
    const form = $('#addQuickCommandForm');
    const nameInput = $('#quickCommandName');
    const commandInput = $('#quickCommandValue'); // Textarea
    const name = nameInput.val().trim();
    const command = commandInput.val().trim(); // Reads from textarea
    const addButton = $('#addQuickCommandButton');

    if (!name || !command) {
        showToast("名称和命令都不能为空。", 'warning');
        return;
    }

    setButtonProcessing(addButton, true);

    $.ajax({
        url: "/quick_commands/add",
        type: "POST",
        data: { name: name, command: command },
        success: function(data) {
            if (data.status === 'success') {
                showToast("快捷命令添加成功。", 'success');
                nameInput.val('');
                commandInput.val('');
                loadQuickCommands(true);
            } else {
                showToast("添加失败: " + data.message, 'danger');
            }
        },
        error: function(jqXHR) {
            const message = jqXHR.responseJSON ? jqXHR.responseJSON.message : "添加快捷命令请求失败。";
            showToast("错误: " + message, 'danger');
        },
        complete: function() {
            setButtonProcessing(addButton, false);
        }
    });
}

function deleteQuickCommand(commandId, buttonElement) {
     if (!confirm('确定要删除这个快捷命令吗？')) {
        return;
     }
    setButtonProcessing(buttonElement, true);
     $.ajax({
        url: `/quick_commands/delete/${commandId}`,
        type: 'DELETE',
        success: function(data) {
            showToast(data.message, data.status);
            if (data.status === 'success') {
                 loadQuickCommands(true);
            }
        },
        error: function(jqXHR) {
            const message = jqXHR.responseJSON ? jqXHR.responseJSON.message : "删除快捷命令请求失败。";
            showToast("删除失败: " + message, 'danger');
            loadQuickCommands(true);
        }
    });
}

$('#addQuickCommandForm').submit(addQuickCommand);

$('#quickCommandsModal').on('shown.bs.modal', function () {
    loadQuickCommands(false);
});
