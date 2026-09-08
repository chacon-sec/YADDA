/// node_agent — JS payload generator (Loki-style script-jacking payload).
///
/// The emitted payload is a standalone Node/Electron script with the listener
/// profile baked in. It registers through the REAL beacon module (watermark
/// be4c0149), so every session menu/console command of the beacon applies to
/// it automatically — this dialog only configures the build.

function GenerateUI(listeners_type)
{
    let labelId = form.create_label("Agent ID:");
    let textId = form.create_textline("auto");
    textId.setPlaceholder("auto = random, or hex id e.g. cafe0011");

    let hline1 = form.create_hline()

    let labelSleep = form.create_label("Sleep (seconds):");
    let spinSleep = form.create_spin();
    spinSleep.setRange(1, 86400);
    spinSleep.setValue(5);

    let labelJitter = form.create_label("Jitter (%):");
    let spinJitter = form.create_spin();
    spinJitter.setRange(0, 100);
    spinJitter.setValue(15);

    let hline2 = form.create_hline()

    let labelSpoof = form.create_label("OS report:");
    let comboSpoof = form.create_combo()
    comboSpoof.addItems(["none", "win10", "win11", "win2022", "win7"]);
    // 'none' = real host info; lab on non-Windows hosts needs a Windows spoof
    // for command attachment (server snapshots OS at registration).

    let checkDebug = form.create_check("Debug output (console.log)");
    checkDebug.setChecked(false);

    let hline3 = form.create_hline()

    let labelWs = form.create_label("Interactive channel (optional):");
    let textWsUrl = form.create_textline("");
    textWsUrl.setPlaceholder("ws://relay-host:18765/tunnel");
    let textWsKey = form.create_textline("");
    textWsKey.setPlaceholder("32 hex chars channel key (empty = disabled)");

    let layout = form.create_gridlayout();
    layout.addWidget(labelId, 0, 0, 1, 1);
    layout.addWidget(textId, 0, 1, 1, 1);
    layout.addWidget(hline1, 1, 0, 1, 2);
    layout.addWidget(labelSleep, 2, 0, 1, 1);
    layout.addWidget(spinSleep, 2, 1, 1, 1);
    layout.addWidget(labelJitter, 3, 0, 1, 1);
    layout.addWidget(spinJitter, 3, 1, 1, 1);
    layout.addWidget(hline2, 4, 0, 1, 2);
    layout.addWidget(labelSpoof, 5, 0, 1, 1);
    layout.addWidget(comboSpoof, 5, 1, 1, 1);
    layout.addWidget(checkDebug, 6, 1, 1, 1);
    layout.addWidget(hline3, 7, 0, 1, 2);
    layout.addWidget(labelWs, 8, 0, 1, 2);
    layout.addWidget(textWsUrl, 9, 1, 1, 1);
    layout.addWidget(textWsKey, 10, 1, 1, 1);

    let container = form.create_container()
    container.put("agent_id", textId)
    container.put("sleep", spinSleep)
    container.put("jitter", spinJitter)
    container.put("os_spoof", comboSpoof)
    container.put("debug", checkDebug)
    container.put("ws_url", textWsUrl)
    container.put("ws_key", textWsKey)

    let panel = form.create_panel()
    panel.setLayout(layout)

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 420,
        ui_width: 520
    }
}
