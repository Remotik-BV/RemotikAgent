/*
Copyright 2019 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Security helper: Validate package/library name
function isValidPackageName(name) {
    if (typeof name !== 'string' || name.length === 0 || name.length > 128) return false;
    // Package names: alphanumeric, dash, underscore, dot, plus
    return /^[a-zA-Z0-9._+-]+$/.test(name);
}

// Security helper: Validate binary name
function isValidBinaryName(name) {
    if (typeof name !== 'string' || name.length === 0 || name.length > 64) return false;
    // Binary names: alphanumeric, dash, underscore
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

function find(name)
{
	// Validate package name to prevent command injection
	if (!isValidPackageName(name)) { return []; }

	switch(process.platform)
	{
		case 'freebsd':
			var ret = [];
			var child = require('child_process').execFile('/bin/sh', ['sh']);
			child.stdout.str = '';
			child.stdout.on('data', function (c) { this.str += c.toString(); });
			child.stdin.write("pkg info " + name + " | tr '\\n' '\\|' | awk ' { a=split($0, t, \"Shared Libs provided:\"); if(a==2) { split(t[2], lib, \":\"); print lib[1]; } }' | tr '\\|' '\\n' | awk '{ if(split($1, res, \".so\")>1) { print $1; } }'\nexit\n");
			child.waitExit();
			try { child.kill(); } catch (e) { }
			var res = child.stdout.str.trim().split('\n');
			for(var i in res)
			{
				if(!res[i].startsWith(name + '.so')) { continue; }
				var v = {name: res[i]};
				// Validate library name from output before using in command
				if (!isValidPackageName(v.name)) { continue; }
				child = require('child_process').execFile('/bin/sh', ['sh']);
				child.stdout.str = '';
				child.stdout.on('data', function (c) { this.str += c.toString(); });
				child.stdin.write('pkg info -l ' + name + ' | grep ' + v.name + ' | awk \'{ a=split($1, tok, "/"); if(tok[a]=="' + v.name + '") { print $1; } }\'\nexit\n');
				child.waitExit();
				try { child.kill(); } catch (e) { }
				v.location = child.stdout.str.trim();
				ret.push(v);
			}
			return(ret);
			break;
	    case 'linux':
	        return (require('monitor-info').getLibInfo(name));
	        break;
	}
}

function hasBinary(bin)
{
    if (process.platform != 'linux' && process.platform != 'freebsd') { return (false); }
    // Validate binary name to prevent command injection
    if (!isValidBinaryName(bin)) { return (false); }
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = '';
    child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("whereis " + bin + " | awk '{ print $2 }'\nexit\n");
    child.waitExit();
    var ret = child.stdout.str.trim() != '';
    try { child.kill(); } catch (e) { }
    return (ret);
}
function findBinary(bin)
{
    if (process.platform != 'linux' && process.platform != 'freebsd') { return (null); }
    // Validate binary name to prevent command injection
    if (!isValidBinaryName(bin)) { return (null); }
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = '';
    child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("whereis " + bin + " | awk '{ print $2 }'\nexit\n");
    child.waitExit();
    var ret = child.stdout.str.trim() != "" ? child.stdout.str.trim() : null;
    try { child.kill(); } catch (e) { }
    return (ret);
}

module.exports = find;
module.exports.hasBinary = hasBinary;
module.exports.findBinary = findBinary;
