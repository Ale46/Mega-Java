/*******************************************************************************
 * Copyright (c) 2013 Ale46.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Public License v3.0
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/gpl.html
 * 
 * Contributors:
 *     @NT2005 - initial API and implementation
 ******************************************************************************/
public class MegaFile {

    private String uid, name, h;
	private long[] key;
    private boolean isDir = false;

    public String getName() {
    	if (name == null)  return "NO NAME"; else  return name;
    	//return name;
    }
    
    public void setKey(long[] k){
    	key  = k;
    }
    
    public long[] getKey(){
    	return key;
    }
    
    public void setHandle(String h){
    	this.h  = h;
    }
    
    public String getHandle(){
    	return h;
    }
    
    public void setName(String name) {
    	
        this.name = name;
    }

    public String getUID() {
        return uid;
    }

    public void setUID(String uid) {
        this.uid = uid;
    }

    public void setAttributes(String attributes) {
    	
    	if (attributes.contains("MEGA")){
    		
    		this.name = attributes.substring(10,attributes.lastIndexOf("\""));
    		
    	}else
    		
    		this.name = attributes;
    }
    
    public void setDirectory(boolean d){
    	isDir = d;
    }
    
    public boolean isDirectory(){
    	return isDir;
    }
}
