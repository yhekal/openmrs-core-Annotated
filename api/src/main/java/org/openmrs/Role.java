/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.hibernate.envers.Audited;
import org.openmrs.util.RoleConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Role is just an aggregater of {@link Privilege}s. {@link User}s contain a number of roles
 * (Users DO NOT contain any privileges directly) Roles can be grouped by inheriting other roles. If
 * a user is given Role A that inherits from Role B, the user has all rights/abilities for both Role
 * A's privileges and for Role B's privileges.
 *
 * @see Privilege
 */
@Audited
public class Role extends BaseChangeableOpenmrsMetadata {
	
	public static final long serialVersionUID = 1234233L;
	
	private static final Logger log = LoggerFactory.getLogger(Role.class);
	
	// Fields
	
	private String role;
	
	private Set<Privilege> privileges;
	
	private Set<Role> inheritedRoles;
	
	private Set<Role> childRoles;
	
	// Constructors
	
	/** default constructor */
	public Role() {
	}
	
	/** constructor with id */
	public Role(String role) {
		this.role = role;
	}
	
	/** constructor with all database required properties */
	public Role(String role, String description) {
		this.role = role;
		setDescription(description);
	}
	
	/**
	 * @return Returns the privileges.
	 */
	// &begin[getPrivileges]
	public Set<Privilege> getPrivileges() {
		return privileges;
	}
	// &end[getPrivileges]
	
	/**
	 * @param privileges The privileges to set.
	 */
	// &begin[setPrivileges]
	public void setPrivileges(Set<Privilege> privileges) {
		this.privileges = privileges;
	}
	// &end[setPrivileges]
	
	@Override
	public String getName() {
		return this.getRole();
	}
	
	/**
	 * Adds the given Privilege to the list of privileges
	 *
	 * @param privilege Privilege to add
	 */
	// &begin[addPrivilege]
	public void addPrivilege(Privilege privilege) {
		if (privileges == null) {
			privileges = new HashSet<>();
		}// &line[containsPrivilege]
		if (privilege != null && !containsPrivilege(privileges, privilege.getPrivilege())) { // &line[getPrivilege]
			privileges.add(privilege);
		}
	}
	// &end[addPrivilege]

	// &begin[containsPrivilege]
	private boolean containsPrivilege(Collection<Privilege> privileges, String privilegeName) {
		for (Privilege privilege : privileges) {
			if (privilege.getPrivilege().equals(privilegeName)) { // &line[getPrivilege]
				return true;
			}
		}
		return false;
	}
	// &end[containsPrivilege]
	
	/**
	 * Removes the given Privilege from the list of privileges
	 *
	 * @param privilege Privilege to remove
	 */
	// &begin[removePrivilege]
	public void removePrivilege(Privilege privilege) {
		if (privileges != null) {
			privileges.remove(privilege);
		}
	}
	// &end[removePrivilege]
	
	/**
	 * @return Returns the role.
	 */
	// &begin[getRole]
	public String getRole() {
		return role;
	}
	// &end[getRole]
	
	/**
	 * @param role The role to set.
	 */
	// &begin[setRole]
	public void setRole(String role) {
		this.role = role;
	}
	// &end[setRole]
	
	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return this.role;
	}
	
	/**
	 * Looks for the given <code>privilegeName</code> privilege name in this roles privileges. This
	 * method does not recurse through the inherited roles
	 *
	 * @param privilegeName String name of a privilege
	 * @return true/false whether this role has the given privilege
	 * <strong>Should</strong> return false if not found
	 * <strong>Should</strong> return true if found
	 * <strong>Should</strong> not fail given null parameter
	 * <strong>Should</strong> return true for any privilegeName if super user
	 */
	// &begin[hasPrivilege]
	public boolean hasPrivilege(String privilegeName) {
		
		if (RoleConstants.SUPERUSER.equals(this.role)) {
			return true;
		}
		
		if (privileges != null) {
			for (Privilege p : privileges) {
				if (p.getPrivilege().equalsIgnoreCase(privilegeName)) { // &line[getPrivilege]
					return true;
				}
			}
		}
		
		return false;
	}
	// &end[hasPrivilege]
	
	/**
	 * @return Returns the inheritedRoles.
	 */
// &begin[getInheritedRoles]
	public Set<Role> getInheritedRoles() {
		if (inheritedRoles == null) {
			inheritedRoles = new HashSet<>();
		}
		return inheritedRoles;
	}
	// &end[getInheritedRoles]
	
	/**
	 * @param inheritedRoles The inheritedRoles to set.
	 */
// &begin[setInheritedRoles]
	public void setInheritedRoles(Set<Role> inheritedRoles) {
		this.inheritedRoles = inheritedRoles;
	}
	// &end[setInheritedRoles]
	
	/**
	 * Convenience method to test whether or not this role extends/ inherits from any other roles
	 *
	 * @return true/false whether this role inherits from other roles
	 */
	// &begin[inheritsRoles]
	public boolean inheritsRoles() {
		return getInheritedRoles() != null && !getInheritedRoles().isEmpty(); // &line[getInheritedRoles]
	}
	// &end[inheritsRoles]
	
	/**
	 * Recursive (if need be) method to return all parent roles of this role
	 *
	 * <strong>Should</strong> only return parent roles
	 * @return Return this role's parents
	 */
// &begin[getAllParentRoles]
	public Set<Role> getAllParentRoles() {
		Set<Role> parents = new HashSet<>();
		if (inheritsRoles()) {
			parents.addAll(this.recurseOverParents(parents));
		}
		return parents;
	}
	// &end[getAllParentRoles]
	
	/**
	 * Returns the full set of roles be looping over inherited roles. Duplicate roles are dropped.
	 *
	 * @param total Roles already looped over
	 * @return Set&lt;Role&gt; Current and inherited roles
	 */
	public Set<Role> recurseOverParents(final Set<Role> total) {
		if (!this.inheritsRoles()) {
			return total;
		}
		
		Set<Role> allRoles = new HashSet<>(total);
		Set<Role> myRoles = new HashSet<>(this.getInheritedRoles());
		myRoles.removeAll(total);
		// prevent an obvious looping problem
		myRoles.remove(this); 
		allRoles.addAll(myRoles);
		
		for (Role r : myRoles) {
			if (r.inheritsRoles()) {
				allRoles.addAll(r.recurseOverParents(allRoles));
			}
		}
		
		log.debug("Total roles: {}", allRoles);
		
		return allRoles;
	}
	
	/**
	 * @since 1.5
	 * @see org.openmrs.OpenmrsObject#getId()
	 */
	@Override
	public Integer getId() {
		throw new UnsupportedOperationException();
	}
	
	/**
	 * @since 1.5
	 * @see org.openmrs.OpenmrsObject#setId(java.lang.Integer)
	 */
	@Override
	public void setId(Integer id) {
		throw new UnsupportedOperationException();
	}
	
	/**
	 * @since 1.9
	 * @return immediate children
	 */
// &begin[getChildRoles]
	public Set<Role> getChildRoles() {
		if (childRoles == null) {
			childRoles = new HashSet<>();
		}
		return childRoles;
	}
	// &end[getChildRoles]
	
	/**
	 * @since 1.9
	 * @param childRoles the immediate children to set
	 */
// &begin[setChildRoles]
	public void setChildRoles(Set<Role> childRoles) {
		this.childRoles = childRoles;
	}
	// &end[setChildRoles]
	
	/**
	 * Convenience method to test whether or not this role is a parent of another role
	 *
	 * @return true/false whether this role is a parent of another role
	 * @since 1.9
	 */
	// &begin[hasChildRoles]
	public boolean hasChildRoles() {
		return getChildRoles() != null && !getChildRoles().isEmpty();  // &line[getChildRoles]
	}
	// &end[hasChildRoles]
	/**
	 * Recursive (if need be) method to return all child roles of this role
	 *
	 * <strong>Should</strong> only return child roles
	 * @return this role's children
	 * @since 1.9
	 */
// &begin[getAllChildRoles]
	public Set<Role> getAllChildRoles() {
		Set<Role> children = new HashSet<>();
		if (hasChildRoles()) {
			children.addAll(this.recurseOverChildren(children));
		}
		return children;
	}
	// &end[getAllChildRoles]
	
	/**
	 * Returns the full set of child roles be looping over children. Duplicate roles are dropped.
	 *
	 * @param total Roles already looped over
	 * @return Set&lt;Role&gt; Current and child roles
	 * @since 1.9
	 */
	public Set<Role> recurseOverChildren(final Set<Role> total) {
		if (!this.hasChildRoles()) { // &line[hasChildRoles]
			return total;
		}
		
		Set<Role> allRoles = new HashSet<>(total);
		
		Set<Role> myRoles = new HashSet<>(this.getChildRoles()); // &line[getChildRoles]
		myRoles.removeAll(total);
		// prevent an obvious looping problem
		myRoles.remove(this); 
		allRoles.addAll(myRoles);
		
		for (Role r : myRoles) {
			if (r.hasChildRoles()) { // &line[hasChildRoles]
				allRoles.addAll(r.recurseOverChildren(allRoles));
			}
		}
		
		log.debug("Total roles: {}", allRoles);
		
		return allRoles;
	}
}
