package com.lauriewired;

import java.io.IOException;

import com.lauriewired.ghidramcp.gui.GuiProgramProvider;
import com.lauriewired.ghidramcp.http.BackendHttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ghidra.app.DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Triangr HTTP server",
	description = "Serves the current program to the Triangr / ghidra-mcp MCP server over a " +
		"local HTTP backend. Host and port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

	private static final String OPTION_CATEGORY_NAME = "Triangr HTTP Server";
	private static final String PORT_OPTION_NAME = "Server Port";
	private static final int DEFAULT_PORT = 8080;
	private static final String HOST_OPTION_NAME = "Server Host IP/NAME";
	private static final String DEFAULT_HOST = "127.0.0.1";

	private BackendHttpServer backend;

	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT, null,
			"The port the Triangr backend listens on. Requires Ghidra restart or plugin reload " +
				"to take effect after changing.");
		options.registerOption(HOST_OPTION_NAME, DEFAULT_HOST, null,
			"The host name or IP the Triangr backend binds to (default 127.0.0.1). A " +
				"non-loopback address exposes the program to the network without " +
				"authentication. Clients must address the backend by this host or a loopback " +
				"name, so bind a specific address rather than 0.0.0.0. Requires Ghidra restart " +
				"or plugin reload to take effect.");
	}

	@Override
	protected void init() {
		super.init();
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
		String host = options.getString(HOST_OPTION_NAME, DEFAULT_HOST);
		backend = new BackendHttpServer(new GuiProgramProvider(tool));
		try {
			backend.start(host, port);
		}
		catch (IOException e) {
			Msg.error(this, "Could not start the Triangr backend on " + host + ":" + port +
				". Is the port in use (for example by another CodeBrowser window)?", e);
		}
	}

	@Override
	protected void dispose() {
		if (backend != null) {
			backend.stop();
			backend = null;
		}
		super.dispose();
	}
}
