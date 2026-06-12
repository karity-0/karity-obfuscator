document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const pipelineStrip = document.getElementById('pipeline-strip');
    const inputScript = document.getElementById('input-script');
    const outputScript = document.getElementById('output-script');
    const inputFilename = document.getElementById('input-filename');
    const elapsedLabel = document.getElementById('elapsed-label');
    const statusMsg = document.getElementById('status-msg');
    const configStatus = document.getElementById('config-status');
    const tooltip = document.getElementById('tooltip');

    // Checkboxes
    const optBytecode = document.getElementById('opt-bytecode');
    const optString = document.getElementById('opt-string');
    const optBoolean = document.getElementById('opt-boolean');
    const optNumber = document.getElementById('opt-number');
    const allCheckboxes = document.querySelectorAll('.opt-checkbox');

    // Buttons
    const openFileBtn = document.getElementById('open-file-btn');
    const clearInputBtn = document.getElementById('clear-input-btn');
    const copyOutputBtn = document.getElementById('copy-output-btn');
    const saveOutputBtn = document.getElementById('save-output-btn');
    const saveConfigBtn = document.getElementById('save-config-btn');
    const runBtn = document.getElementById('run-btn');

    let pyapi = null;
    let originalFilename = "obfuscated.lua";

    // pywebview 준비 체크
    if (window.pywebview && window.pywebview.api) {
        onBackendReady();
    } else {
        window.addEventListener('pywebviewready', onBackendReady);
    }

    async function onBackendReady() {
        pyapi = window.pywebview.api;
        setStatus('백엔드 연결 완료', 'info');
        
        try {
            const savedConfig = await pyapi.load_config();
            applySavedConfig(savedConfig);
            updatePipelineStrip();
        } catch (err) {
            console.error('설정 로드 실패:', err);
        }
        
        // 툴팁 이벤트 바인딩 초기화
        initTooltipEvents();
    }

    // 체크박스 변동 시 하단 시각화 스트립 업데이트
    allCheckboxes.forEach(cb => {
        cb.addEventListener('change', updatePipelineStrip);
    });

    function updatePipelineStrip() {
        const nodes = [];
        if (optBytecode.checked) nodes.push('Bytecode Obf');
        nodes.push('VM'); 
        if (optString.checked) nodes.push('String Obf');
        if (optBoolean.checked) nodes.push('Boolean Obf');
        if (optNumber.checked) nodes.push('Number Obf');
        nodes.push('Rename & Minify'); 
        
        pipelineStrip.innerHTML = nodes
            .map(name => `<div class="pipeline-node">${name}</div>`)
            .join('<div class="pipeline-arrow">→</div>');
    }

    // ------------------------------------------------------------
    // 전역 툴팁 핸들러 인터페이스
    // ------------------------------------------------------------
    function initTooltipEvents() {
        const hintElements = document.querySelectorAll('[data-hint]');
        
        hintElements.forEach(el => {
            el.addEventListener('mouseenter', (e) => {
                const hintText = el.getAttribute('data-hint');
                if (!hintText) return;
                
                tooltip.textContent = hintText;
                tooltip.classList.add('active');
            });
            
            el.addEventListener('mousemove', (e) => {
                // 마우스 포인터 우하단에 살짝 여백을 주고 배치
                tooltip.style.left = (e.pageX + 12) + 'px';
                tooltip.style.top = (e.pageY + 12) + 'px';
            });
            
            el.addEventListener('mouseleave', () => {
                tooltip.classList.remove('active');
            });
        });
    }

    // ------------------------------------------------------------
    // 설정값 적용 및 페이로드 조립 제어 규칙
    // ------------------------------------------------------------
    function applySavedConfig(savedConfig) {
        if (!savedConfig) return;
        
        const mainPasses = savedConfig.passes || [];
        optBytecode.checked = mainPasses.includes('string_obf') || mainPasses.includes('number_obf');

        const vmPasses = savedConfig.vm_output_passes || [];
        optString.checked = vmPasses.includes('string_encode') || vmPasses.includes('string_obf');
        optBoolean.checked = vmPasses.includes('boolean_obf');
        optNumber.checked = vmPasses.includes('number_obf');
    }

    function buildPayloadConfig() {
        const passes = [];
        if (optBytecode.checked) {
            passes.push("string_obf", "boolean_obf", "number_obf");
        }
        passes.push("vm"); 

        const vm_output_passes = [];
        if (optString.checked) {
            vm_output_passes.push("string_obf");
        }
        if (optBoolean.checked) {
            vm_output_passes.push("boolean_obf");
        }
        if (optNumber.checked) {
            vm_output_passes.push("number_obf");
        }
        
        vm_output_passes.push("rename_obf", "minify");

        return { passes, vm_output_passes };
    }

    // ------------------------------------------------------------
    // 원격 및 로컬 입출력 제어 이벤트 핸들러
    // ------------------------------------------------------------

    saveConfigBtn.addEventListener('click', async () => {
        if (!pyapi) return;
        const config = buildPayloadConfig();
        const res = await pyapi.save_config(config);
        
        if (res && res.ok) {
            configStatus.textContent = '설정 저장 완료';
            configStatus.classList.add('active');
            setTimeout(() => {
                configStatus.textContent = '';
                configStatus.classList.remove('active');
            }, 2000);
        }
    });

    openFileBtn.addEventListener('click', async () => {
        if (!pyapi) return;
        setStatus('파일 선택 중...', 'info');
        const res = await pyapi.pick_input_file();
        
        if (!res) {
            setStatus('파일 열기 취소됨', 'info');
            return;
        }
        if (res.error) {
            setStatus(res.error, 'error');
            alert(res.error);
            return;
        }

        inputScript.value = res.content;
        inputFilename.textContent = res.name;
        originalFilename = res.name;
        setStatus('파일을 불러왔습니다.', 'success');
    });

    clearInputBtn.addEventListener('click', () => {
        inputScript.value = '';
        inputFilename.textContent = '';
        originalFilename = "obfuscated.lua";
        setStatus('입력창 초기화됨', 'info');
    });

    copyOutputBtn.addEventListener('click', () => {
        const content = outputScript.value;
        if (!content.trim()) return;

        navigator.clipboard.writeText(content)
            .then(() => {
                const prevLabel = elapsedLabel.textContent;
                elapsedLabel.textContent = '복사 완료!';
                setTimeout(() => { elapsedLabel.textContent = prevLabel; }, 1500);
            })
            .catch(() => alert('클립보드 복사 실패'));
    });

    saveOutputBtn.addEventListener('click', async () => {
        if (!pyapi) return;
        const content = outputScript.value;
        if (!content.trim()) return alert('저장할 결과가 없습니다.');

        const defaultName = originalFilename.startsWith('obf_') ? originalFilename : `obf_${originalFilename}`;
        setStatus('파일 저장 중...', 'info');
        const res = await pyapi.save_output(content, defaultName);
        
        if (res.ok) setStatus(`저장 성공: ${res.path}`, 'success');
        else setStatus('저장 취소 또는 실패', 'info');
    });

    runBtn.addEventListener('click', async () => {
        if (!pyapi) return;
        const script = inputScript.value;

        if (!script.trim()) {
            setStatus('입력 코드가 없습니다.', 'error');
            return;
        }

        setStatus('난독화 진행 중...', 'info');
        runBtn.disabled = true;

        const { passes, vm_output_passes } = buildPayloadConfig();
        const payload = { script, passes, vm_output_passes };

        const res = await pyapi.run_obfuscation(payload);
        runBtn.disabled = false;

        if (res.ok) {
            outputScript.value = res.output;
            elapsedLabel.textContent = `${res.elapsed}s`;
            setStatus('난독화 완료', 'success');
        } else {
            outputScript.value = res.error;
            elapsedLabel.textContent = '에러';
            setStatus('오류가 발생했습니다.', 'error');
        }
    });

    function setStatus(msg, type) {
        statusMsg.textContent = msg;
        statusMsg.className = `status-msg status-${type}`;
    }
});