document.addEventListener('DOMContentLoaded', () => {
    // ------------------------------------------------------------
    // 커스텀 타이틀바 - 윈도우 컨트롤
    // ------------------------------------------------------------
    const winMinBtn = document.getElementById('win-min');
    const winMaxBtn = document.getElementById('win-max');
    const winCloseBtn = document.getElementById('win-close');

    winMinBtn?.addEventListener('click', () => {
        window.pywebview?.api?.window_minimize?.();
    });

    winMaxBtn?.addEventListener('click', () => {
        window.pywebview?.api?.window_toggle_maximize?.();
    });

    winCloseBtn?.addEventListener('click', () => {
        window.pywebview?.api?.window_close?.();
    });

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
    const optTable  = document.getElementById('opt-table');
    const optFunction  = document.getElementById('opt-function');
    const optAntiDebug = document.getElementById('opt-anti-debug');
    const allCheckboxes = document.querySelectorAll('.opt-checkbox');

    const vmoptFakeHandlers = document.getElementById('vmopt-fake-handlers');
    const vmoptMutateHandlers = document.getElementById('vmopt-mutate-handlers');
    const vmoptJunkInstructions = document.getElementById('vmopt-junk-instructions');
    const vmoptJunkRate = document.getElementById('vmopt-junk-rate');
    const vmoptJunkRateValue = document.getElementById('vmopt-junk-rate-value');
    const allVmOptCheckboxes = document.querySelectorAll('.vmopt-checkbox');

    vmoptJunkRate?.addEventListener('input', () => {
        vmoptJunkRateValue.textContent = Number(vmoptJunkRate.value).toFixed(2);
    });

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
        if (optTable.checked) nodes.push("Table Obf");
        if (optFunction.checked) nodes.push("Function Obf");
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
        optAntiDebug.checked = mainPasses.includes('anti_debug');

        const vmPasses = savedConfig.vm_output_passes || [];
        optString.checked = vmPasses.includes('string_encode') || vmPasses.includes('string_obf');
        optBoolean.checked = vmPasses.includes('boolean_obf');
        optNumber.checked = vmPasses.includes('number_obf');
        optTable.checked = vmPasses.includes("table_obf");
        optFunction.checked = vmPasses.includes("function_obf");       

        const vmOptions = savedConfig.vm_options || {};
        vmoptFakeHandlers.checked = vmOptions.fake_handlers !== false;
        vmoptMutateHandlers.checked = vmOptions.mutate_handlers !== false;
        vmoptJunkInstructions.checked = vmOptions.junk_instructions !== false;

        const junkRate = vmOptions.junk_rate;
        vmoptJunkRate.value = (typeof junkRate === 'number') ? junkRate : 0.15;
        vmoptJunkRateValue.textContent = Number(vmoptJunkRate.value).toFixed(2);
    }

    function buildPayloadConfig() {
        const passes = [];
        if (optAntiDebug.checked) {
            passes.push("anti_debug");
        }
        if (optBytecode.checked) {
            passes.push("string_obf", "boolean_obf", "number_obf", "table_obf", "function_obf");
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
        if (optTable.checked) {
            vm_output_passes.push("table_obf");
        }
        if (optFunction.checked) {
            vm_output_passes.push("function_obf");
        }
        
        vm_output_passes.push("rename_obf", "minify");

        const vm_options = {
            fake_handlers: vmoptFakeHandlers.checked,
            mutate_handlers: vmoptMutateHandlers.checked,
            junk_instructions: vmoptJunkInstructions.checked,
            junk_rate: Number(vmoptJunkRate.value),
        };

        return { passes, vm_output_passes, vm_options };
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

        const { passes, vm_output_passes, vm_options } = buildPayloadConfig();
        const payload = { script, passes, vm_output_passes, vm_options };

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