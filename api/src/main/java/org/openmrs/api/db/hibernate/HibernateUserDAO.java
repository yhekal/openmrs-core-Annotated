/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.api.db.hibernate;

import javax.persistence.Query;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Join;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.openmrs.Person;
import org.openmrs.PersonName;
import org.openmrs.Privilege;
import org.openmrs.Role;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.Daemon;
import org.openmrs.api.db.DAOException;
import org.openmrs.api.db.LoginCredential;
import org.openmrs.api.db.UserDAO;
import org.openmrs.patient.impl.LuhnIdentifierValidator;
import org.openmrs.util.OpenmrsConstants;
import org.openmrs.util.Security;
import org.openmrs.util.UserByNameComparator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Hibernate specific database methods for the UserService
 * 
 * @see org.openmrs.api.context.Context
 * @see org.openmrs.api.db.UserDAO
 * @see org.openmrs.api.UserService
 */
public class HibernateUserDAO implements UserDAO {
	
	private static final Logger log = LoggerFactory.getLogger(HibernateUserDAO.class);
	
	/**
	 * Hibernate session factory
	 */
	private SessionFactory sessionFactory;
	
	/**
	 * Set session factory
	 * 
	 * @param sessionFactory
	 */
	public void setSessionFactory(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
	
	/**
	 * @see org.openmrs.api.UserService#saveUser(org.openmrs.User, java.lang.String, java.lang.String)
	 */
	@Override
	public User saveUser(User user, String password) {
		
		// only change the user's password when creating a new user
		boolean isNewUser = user.getUserId() == null;
		
		sessionFactory.getCurrentSession().saveOrUpdate(user); // &line[getCurrentSession]
		
		if (isNewUser && password != null) {
			/* In OpenMRS, we are using generation strategy as native which will convert to IDENTITY 
			 for MySQL and SEQUENCE for PostgreSQL. When using IDENTITY strategy, hibernate directly 
			 issues insert statements where as with  SEQUENCE strategy hibernate only increments 
			 sequences and issues insert on session flush ( batching is possible) . 
			 PostgreSQL behaves differently than MySQL because it makes use of SEQUENCE strategy. 
			*/
			sessionFactory.getCurrentSession().flush(); // &line[getCurrentSession]
			
			//update the new user with the password
			String salt = Security.getRandomToken(); // &line[getRandomToken]
			String hashedPassword = Security.encodeString(password + salt); // &line[encodeString]
			
			updateUserPassword(hashedPassword, salt, Context.getAuthenticatedUser().getUserId(), new Date(), user  // &line[updateUserPassword]
			        .getUserId());
		}
		
		return user;
	}
	
	/**
	 * @see org.openmrs.api.UserService#getUserByUsername(java.lang.String)
	 */
	@Override
	@SuppressWarnings("unchecked")
	public User getUserByUsername(String username) {
		Query query = sessionFactory.getCurrentSession().createQuery( // &line[getCurrentSession]
		    "from User u where u.retired = '0' and (u.username = ?0 or u.systemId = ?1)");
		query.setParameter(0, username);
		query.setParameter(1, username);
		List<User> users = query.getResultList();
		
		if (users == null || users.isEmpty()) {
			log.warn("request for username '" + username + "' not found");
			return null;
		}
		
		return users.get(0);
	}
	
	/**
	 * @see org.openmrs.api.UserService#getUserByEmail(java.lang.String)
	 */
	@Override
	public User getUserByEmail(String email) {
		Session session = sessionFactory.getCurrentSession(); // &line[getCurrentSession]
		CriteriaBuilder cb = session.getCriteriaBuilder();
		CriteriaQuery<User> cq = cb.createQuery(User.class);
		Root<User> root = cq.from(User.class);

		cq.where(cb.equal(cb.lower(root.get("email")), email.toLowerCase()));

		return session.createQuery(cq).uniqueResult();
	}
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getLoginCredentialByActivationKey(java.lang.String)
	 */
	@Override
		// &begin[getLoginCredentialByActivationKey]
	public LoginCredential getLoginCredentialByActivationKey(String activationKey) {
		String key = Security.encodeString(activationKey);
		Session session = sessionFactory.getCurrentSession(); // &line[getCurrentSession]
		CriteriaBuilder cb = session.getCriteriaBuilder();
		CriteriaQuery<LoginCredential> cq = cb.createQuery(LoginCredential.class);
		Root<LoginCredential> root = cq.from(LoginCredential.class);

		cq.where(cb.like(cb.lower(root.get("activationKey")), MatchMode.START.toCaseSensitivePattern(key)));

		LoginCredential loginCred = session.createQuery(cq).uniqueResult();

		if(loginCred != null) {
			String[] credTokens = loginCred.getActivationKey().split(":"); // &line[getActivationKey]
			if(credTokens[0].equals(key)){
				return loginCred;
			}
		}
		return null;
	}
	// &end[getLoginCredentialByActivationKey]
	
	/**
	 * @see org.openmrs.api.UserService#hasDuplicateUsername(org.openmrs.User)
	 */
	@Override
	public boolean hasDuplicateUsername(String username, String systemId, Integer userId) {
		if (username == null || username.length() == 0) {
			username = "-";
		}
		if (systemId == null || systemId.length() == 0) {
			systemId = "-";
		}
		
		if (userId == null) {
			userId = -1;
		}
		
		String usernameWithCheckDigit = username;
		try {
			//Hardcoding in Luhn since past user IDs used this validator.
			usernameWithCheckDigit = new LuhnIdentifierValidator().getValidIdentifier(username);
		}
		catch (Exception e) {}
		
		Query query = sessionFactory
		        .getCurrentSession() // &line[getCurrentSession]
		        .createQuery(
		            "select count(*) from User u where (u.username = :uname1 or u.systemId = :uname2 or u.username = :sysid1 or u.systemId = :sysid2 or u.systemId = :uname3) and u.userId <> :uid");
		query.setParameter("uname1", username);
		query.setParameter("uname2", username);
		query.setParameter("sysid1", systemId);
		query.setParameter("sysid2", systemId);
		query.setParameter("uname3", usernameWithCheckDigit);
		query.setParameter("uid", userId);
		
		Long count = JpaUtils.getSingleResultOrNull(query);
		
		log.debug("# users found: " + count);
		return (count != null && count != 0);
	}
	
	/**
	 * @see org.openmrs.api.UserService#getUser(java.lang.Integer)
	 */
	@Override
	public User getUser(Integer userId) {

		return sessionFactory.getCurrentSession().get(User.class, userId); // &line[getCurrentSession]
	}
	
	/**
	 * @see org.openmrs.api.UserService#getAllUsers()
	 */
	@Override
	@SuppressWarnings("unchecked")
	public List<User> getAllUsers() throws DAOException {
		return sessionFactory.getCurrentSession().createQuery("from User where not uuid = :daemonUserUuid order by userId") // &line[getCurrentSession]
		        .setParameter("daemonUserUuid", Daemon.getDaemonUserUuid()).list();
	}
	
	/**
	 * @see org.openmrs.api.UserService#deleteUser(org.openmrs.User)
	 */
	@Override
	public void deleteUser(User user) {
		sessionFactory.getCurrentSession().delete(user);
	}
	
	/**
	 * @see org.openmrs.api.UserService#getUsersByRole(org.openmrs.Role)
	 */
	public List<User> getUsersByRole(Role role) {
		Session session = sessionFactory.getCurrentSession(); // &line[getCurrentSession]
		CriteriaBuilder cb = session.getCriteriaBuilder();
		CriteriaQuery<User> cq = cb.createQuery(User.class);
		Root<User> root = cq.from(User.class);
		Join<User, Role> roles = root.join("roles");

		Predicate roleLike = cb.like(roles.get("role"), role.getRole()); // &line[getRole]
		Predicate uuidNotEqual = cb.notEqual(root.get("uuid"), Daemon.getDaemonUserUuid());

		cq.where(roleLike, uuidNotEqual).orderBy(cb.asc(root.get("username")));

		return session.createQuery(cq).getResultList();
	}
	
	/**
	 * @see org.openmrs.api.UserService#getAllPrivileges()
	 */
	@Override
	@SuppressWarnings("unchecked")
		// &begin[getAllPrivileges]
	public List<Privilege> getAllPrivileges() throws DAOException {
		return sessionFactory.getCurrentSession().createQuery("from Privilege p order by p.privilege").list(); // &line[getCurrentSession]
	}
	// &end[getAllPrivileges]
	
	/**
	 * @see org.openmrs.api.UserService#getPrivilege(String)
	 */
	@Override
		// &begin[getPrivilege]
	public Privilege getPrivilege(String p) throws DAOException {
		return sessionFactory.getCurrentSession().get(Privilege.class, p); // &line[getCurrentSession]
	}
	// &end[getPrivilege]
	
	/**
	 * @see org.openmrs.api.db.UserDAO#deletePrivilege(org.openmrs.Privilege)
	 */
	@Override
		// &begin[deletePrivilege]
	public void deletePrivilege(Privilege privilege) throws DAOException {
		sessionFactory.getCurrentSession().delete(privilege); // &line[getCurrentSession]
	}
	// &end[deletePrivilege]
	
	/**
	 * @see org.openmrs.api.db.UserDAO#savePrivilege(org.openmrs.Privilege)
	 */
	@Override
		// &begin[savePrivilege]
	public Privilege savePrivilege(Privilege privilege) throws DAOException {
		sessionFactory.getCurrentSession().saveOrUpdate(privilege); // &line[getCurrentSession]
		return privilege;
	}
	// &end[savePrivilege]
	
	/**
	 * @see org.openmrs.api.UserService#purgeRole(org.openmrs.Role)
	 */
	@Override
// &begin[deleteRole]
	public void deleteRole(Role role) throws DAOException {
		sessionFactory.getCurrentSession().delete(role); // &line[getCurrentSession]
	}
	// &end[deleteRole]
	
	/**
	 * @see org.openmrs.api.UserService#saveRole(org.openmrs.Role)
	 */
	@Override
// &begin[saveRole]
	public Role saveRole(Role role) throws DAOException {
		sessionFactory.getCurrentSession().saveOrUpdate(role); // &line[getCurrentSession]
		return role;
	}
	// &end[saveRole]
	
	/**
	 * @see org.openmrs.api.UserService#getAllRoles()
	 */
	@Override
	@SuppressWarnings("unchecked")
// &begin[getAllRoles]
	public List<Role> getAllRoles() throws DAOException {
		return sessionFactory.getCurrentSession().createQuery("from Role r order by r.role").list();
	}
	// &end[getAllRoles]
	/**
	 * @see org.openmrs.api.UserService#getRole(String)
	 */
	@Override
// &begin[getRole]
	public Role getRole(String r) throws DAOException {
		return sessionFactory.getCurrentSession().get(Role.class, r);
	}
	// &end[getRole]
	
	/**
	 * @see org.openmrs.api.db.UserDAO#changePassword(org.openmrs.User, java.lang.String)
	 */
	@Override
		// &begin[changePassword]
	public void changePassword(User u, String pw) throws DAOException {
		User authUser = Context.getAuthenticatedUser();
		
		if (authUser == null) {
			authUser = u;
		}
		
		log.debug("updating password");
		String salt = getLoginCredential(u).getSalt(); // &line[getLoginCredential]
		if (StringUtils.isBlank(salt)) {
			salt = Security.getRandomToken(); // &line[getRandomToken]
		}
		String newHashedPassword = Security.encodeString(pw + salt);
		
		updateUserPassword(newHashedPassword, salt, authUser.getUserId(), new Date(), u.getUserId());  // &line[updateUserPassword]
		
	}
	// &end[changePassword]
	/**
	 * @see org.openmrs.api.db.UserDAO#changeHashedPassword(User, String, String)
	 */
	@Override
		// &begin[changeHashedPassword]
	public void changeHashedPassword(User user, String hashedPassword, String salt) throws DAOException {
		User authUser = Context.getAuthenticatedUser(); // &line[getAuthenticatedUser]
		updateUserPassword(hashedPassword, salt, authUser.getUserId(), new Date(), user.getUserId());// &line[updateUserPassword]
	}
	// &end[changeHashedPassword]
	
	/**
	 * @param newHashedPassword
	 * @param salt
	 * @param userId
	 * @param date
	 * @param userId2
	 */
	// &begin[updateUserPassword]
	private void updateUserPassword(String newHashedPassword, String salt, Integer changedBy, Date dateChanged,
	        Integer userIdToChange) {
		User changeForUser = getUser(userIdToChange);
		if (changeForUser == null) {
			throw new DAOException("Couldn't find user to set password for userId=" + userIdToChange);
		}
		User changedByUser = getUser(changedBy);
		LoginCredential credentials = getLoginCredential(changeForUser);
		credentials.setUserId(userIdToChange);
		credentials.setHashedPassword(newHashedPassword); // &line[setHashedPassword]
		credentials.setSalt(salt); // &line[setSalt]
		credentials.setChangedBy(changedByUser);
		credentials.setDateChanged(dateChanged);
		credentials.setUuid(changeForUser.getUuid());
		
		sessionFactory.getCurrentSession().merge(credentials);
		
		// reset lockout 
		changeForUser.setUserProperty(OpenmrsConstants.USER_PROPERTY_LOCKOUT_TIMESTAMP, "");
		changeForUser.setUserProperty(OpenmrsConstants.USER_PROPERTY_LOGIN_ATTEMPTS, OpenmrsConstants.ZERO_LOGIN_ATTEMPTS_VALUE);
		saveUser(changeForUser, null);
	}
	// &end[updateUserPassword]
	
	/**
	 * @see org.openmrs.api.UserService#changePassword(java.lang.String, java.lang.String)
	 */
	@Override
		// &begin[changePassword]
	public void changePassword(String oldPassword, String newPassword) throws DAOException {
		User u = Context.getAuthenticatedUser();  // &line[getAuthenticatedUser]
		LoginCredential credentials = getLoginCredential(u); // &line[getLoginCredential]
		if (!credentials.checkPassword(oldPassword)) { // &line[checkPassword]
			log.error("Passwords don't match");
			throw new DAOException("Passwords don't match");
		}
		
		log.info("updating password for {}", u.getUsername());
		
		// update the user with the new password
		String salt = credentials.getSalt(); // &line[getSalt]
		String newHashedPassword = Security.encodeString(newPassword + salt);  // &line[encodeString]
		updateUserPassword(newHashedPassword, salt, u.getUserId(), new Date(), u.getUserId());// &line[updateUserPassword]
	}
	// &end[changePassword]
	
	/**
	 * @see org.openmrs.api.UserService#changeQuestionAnswer(java.lang.String, java.lang.String,
	 *      java.lang.String)
	 */
	@Override
		// &begin[changeQuestionAnswer]
	public void changeQuestionAnswer(String pw, String question, String answer) throws DAOException {
		User u = Context.getAuthenticatedUser();  // &line[getAuthenticatedUser]
		
		LoginCredential credentials = getLoginCredential(u);  // &line[getLoginCredential]
		if (!credentials.checkPassword(pw)) { // &line[checkPassword]
			log.error("Passwords don't match");
			throw new DAOException("Passwords don't match");
		}
		
		changeQuestionAnswer(u, question, answer);
	}
	// &end[changeQuestionAnswer]
	
	/**
	 * @see org.openmrs.api.UserService#changeQuestionAnswer(User, String, String)
	 */
	@Override
		// &begin[changeQuestionAnswer]
	public void changeQuestionAnswer(User u, String question, String answer) throws DAOException {
		log.info("Updating secret question and answer for " + u.getUsername());
		
		LoginCredential credentials = getLoginCredential(u); // &line[getLoginCredential]
		credentials.setSecretQuestion(question); // &line[setSecretQuestion]
		String hashedAnswer = Security.encodeString(answer.toLowerCase() + credentials.getSalt()); // &line[encodeString]
		credentials.setSecretAnswer(hashedAnswer); // &line[setSecretAnswer]
		credentials.setDateChanged(new Date());
		credentials.setChangedBy(u);
		
		updateLoginCredential(credentials); // &line[updateLoginCredential]
	}
	// &end[changeQuestionAnswer]
	
	/**
	 * @see org.openmrs.api.UserService#isSecretAnswer(User, java.lang.String)
	 */
	@Override
		// &begin[isSecretAnswer]
	public boolean isSecretAnswer(User u, String answer) throws DAOException {
		
		if (StringUtils.isEmpty(answer)) {
			return false;
		}
		
		LoginCredential credentials = getLoginCredential(u); // &line[getLoginCredential]
		String answerOnRecord = credentials.getSecretAnswer(); // &line[getSecretAnswer]
		String hashedAnswer = Security.encodeString(answer.toLowerCase() + credentials.getSalt()); // &line[encodeString]
		return (hashedAnswer.equals(answerOnRecord));
	}
	// &begin[isSecretAnswer]
	
	/**
	 * @see UserDAO#getUsers(String, List, boolean, Integer, Integer)
	 */
	@Override
	@SuppressWarnings("unchecked")
	public List<User> getUsers(String name, List<Role> roles, boolean includeRetired, Integer start, Integer length) {
		
		String hqlSelectStart = "select distinct user from User as user inner join user.person.names as name ";
		Query query = createUserSearchQuery(name, roles, includeRetired, hqlSelectStart);
		
		if (start != null) {
			query.setFirstResult(start);
		}
		if (length != null && length > 0) {
			query.setMaxResults(length);
		}
		
		List<User> returnList = query.getResultList();
		
		if (!CollectionUtils.isEmpty(returnList)) {
			returnList.sort(new UserByNameComparator());
		}
		
		return returnList;
	}
	
	/**
	 * @see org.openmrs.api.UserService#generateSystemId()
	 */
	@Override
	public Integer generateSystemId() {
		
		String hql = "select max(userId) from User";
		
		Query query = sessionFactory.getCurrentSession().createQuery(hql);
		
		Object object = JpaUtils.getSingleResultOrNull(query);
		
		Integer id;
		if (object instanceof Number) {
			id = ((Number) JpaUtils.getSingleResultOrNull(query)).intValue() + 1;
		} else {
			log.warn("What is being returned here? Definitely nothing expected object value: '" + object + "' of class: "
			        + object.getClass());
			id = 1;
		}
		
		return id;
	}
	
	/**
	 * @see org.openmrs.api.UserService#getUsersByName(java.lang.String, java.lang.String, boolean)
	 */
	@Override
	public List<User> getUsersByName(String givenName, String familyName, boolean includeRetired) {
		Session session = sessionFactory.getCurrentSession();
		CriteriaBuilder cb = session.getCriteriaBuilder();
		CriteriaQuery<User> cq = cb.createQuery(User.class);
		Root<User> root = cq.from(User.class);

		Join<User, Person> personJoin = root.join("person");
		Join<Person, PersonName> nameJoin = personJoin.join("names");

		List<Predicate> predicates = new ArrayList<>();
		predicates.add(cb.equal(nameJoin.get("givenName"), givenName));
		predicates.add(cb.equal(nameJoin.get("familyName"), familyName));
		predicates.add(cb.notEqual(root.get("uuid"), Daemon.getDaemonUserUuid()));


		if (!includeRetired) {
			predicates.add(cb.isFalse(root.get("retired")));
		}

		cq.where(predicates.toArray(predicates.toArray(new Predicate[]{}))).distinct(true);

		return new ArrayList<>(session.createQuery(cq).getResultList());
	}
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getPrivilegeByUuid(java.lang.String)
	 */
	@Override
	public Privilege getPrivilegeByUuid(String uuid) {
		return HibernateUtil.getUniqueEntityByUUID(sessionFactory, Privilege.class, uuid);
	}
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getRoleByUuid(java.lang.String)
	 */
	@Override
// &begin[getRoleByUuid]
	public Role getRoleByUuid(String uuid) {
		return HibernateUtil.getUniqueEntityByUUID(sessionFactory, Role.class, uuid);
	}
	// &begin[getRoleByUuid]
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getUserByUuid(java.lang.String)
	 */
	@Override
	public User getUserByUuid(String uuid) {
		User ret = null;
		
		if (uuid != null) {
			uuid = uuid.trim();
			ret = HibernateUtil.getUniqueEntityByUUID(sessionFactory, User.class, uuid);
		}
		
		return ret;
	}
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getLoginCredential(org.openmrs.User)
	 */
	@Override
		// &begin[getLoginCredential]
	public LoginCredential getLoginCredential(User user) {
		return sessionFactory.getCurrentSession().get(LoginCredential.class, user.getUserId()); // &line[getCurrentSession]
	}
	// &begin[getLoginCredential]
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getLoginCredential(org.openmrs.User)
	 */
	@Override
		// &begin[getLoginCredentialByUuid]
	public LoginCredential getLoginCredentialByUuid(String uuid) {
		if (uuid == null) {
			return null;
		} else {
			return HibernateUtil.getUniqueEntityByUUID(sessionFactory, LoginCredential.class, uuid.trim()); 
		}
	}
	// &begin[getLoginCredentialByUuid]
	
	/**
	 * @see org.openmrs.api.db.UserDAO#updateLoginCredential(LoginCredential)
	 */
	@Override
		// &begin[updateLoginCredential]
	public void updateLoginCredential(LoginCredential credential) {
		sessionFactory.getCurrentSession().update(credential);
	}
	// &end[updateLoginCredential]
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getUsersByPerson(org.openmrs.Person, boolean)
	 */
	@Override
	public List<User> getUsersByPerson(Person person, boolean includeRetired) {
		Session session = sessionFactory.getCurrentSession();
		CriteriaBuilder cb = session.getCriteriaBuilder();
		CriteriaQuery<User> cq = cb.createQuery(User.class);
		Root<User> root = cq.from(User.class);

		List<Predicate> predicates = new ArrayList<>();
		predicates.add(cb.notEqual(root.get("uuid"), Daemon.getDaemonUserUuid()));

		if (person != null) {
			predicates.add(cb.equal(root.get("person"), person));
		}
		if (!includeRetired) {
			predicates.add(cb.isFalse(root.get("retired")));
		}

		cq.where(predicates.toArray(new Predicate[]{}));
		return session.createQuery(cq).getResultList();
	}
	
	/**
	 * @see org.openmrs.api.db.UserDAO#getCountOfUsers(String, List, boolean)
	 */
	@Override
	public Integer getCountOfUsers(String name, List<Role> roles, boolean includeRetired) {
		String hqlSelectStart = "select count(distinct user) from User as user inner join user.person.names as name ";
		Query query = createUserSearchQuery(name, roles, includeRetired, hqlSelectStart);
		
		return ((Long) JpaUtils.getSingleResultOrNull(query)).intValue();
	}
	
	/**
	 * Utility methods that creates a hibernate query object from the specified arguments
	 * 
	 * @param name The name of the user to search against
	 * @param roles the roles to match against
	 * @param includeRetired Specifies if retired users should be included or not
	 * @param hqlSelectStart The starting phrase of the select statement that includes the joined
	 *            tables
	 * @return the created hibernate query object
	 */
	private Query createUserSearchQuery(String name, List<Role> roles, boolean includeRetired, String hqlSelectStart) {
		
		log.debug("name: " + name);
		
		name = HibernateUtil.escapeSqlWildcards(name, sessionFactory);
		
		// Create an HQL query like this:
		// select distinct user
		// from User as user inner join user.person.names as name inner join user.roles as role
		// where (user.username like :name1 or ...and for systemId givenName familyName familyName2...)
		//   and (user.username like :name2 or ...and for systemId givenName familyName familyName2...)
		//   ...repeat for all name fragments...
		//	 and role in :roleList 
		//   and user.retired = false
		// order by username asc
		List<String> criteria = new ArrayList<>();
		int counter = 0;
		Map<String, String> namesMap = new HashMap<>();
		if (name != null) {
			name = name.replace(", ", " ");
			String[] names = name.split(" ");
			for (String n : names) {
				if (n != null && n.length() > 0) {
					// compare each fragment of the query against username, systemId, given, middle, family, and family2
					String key = "name" + ++counter;
					String value = n + "%";
					namesMap.put(key, value);
					criteria.add("(user.username like :" + key + " or user.systemId like :" + key
					        + " or name.givenName like :" + key + " or name.middleName like :" + key
					        + " or name.familyName like :" + key + " or name.familyName2 like :" + key + ")");
				}
			}
		}
		
		if (!includeRetired) {
			criteria.add("user.retired = false");
		}
		
		// build the hql query
		StringBuilder hql = new StringBuilder(hqlSelectStart);
		boolean searchOnRoles = false;
		
		if (CollectionUtils.isNotEmpty(roles)) {
			hql.append("inner join user.roles as role ");
			searchOnRoles = true;
		}
		hql.append("where user.uuid != :DAEMON_USER_UUID ");
		
		if (!criteria.isEmpty() || searchOnRoles) {
			hql.append("and ");
		}
		for (Iterator<String> i = criteria.iterator(); i.hasNext();) {
			hql.append(i.next()).append(" ");
			if (i.hasNext()) {
				hql.append("and ");
			}
		}
		
		//Match against the specified roles
		if (searchOnRoles) {
			if (!criteria.isEmpty()) {
				hql.append(" and ");
			}
			hql.append(" role in (:roleList)");
		}
		
		Query query = sessionFactory.getCurrentSession().createQuery(hql.toString());
		query.setParameter("DAEMON_USER_UUID", Daemon.getDaemonUserUuid());
		for (Map.Entry<String, String> e : namesMap.entrySet()) {
			query.setParameter(e.getKey(), e.getValue());
		}
		
		if (searchOnRoles) {
			query.setParameter("roleList", roles);
		}
		
		return query;
	}
	
	/**
	 * @see org.openmrs.api.db.UserDAO#createActivationKey(org.openmrs.User)
	 */
	@Override
		// &begin[setUserActivationKey]
	public void setUserActivationKey(LoginCredential credentials) {		
			sessionFactory.getCurrentSession().merge(credentials);	// &line[getCurrentSession]
	}
	// &end[setUserActivationKey]

	/**
	 * @see org.openmrs.api.db.UserDAO#getLastLoginTime(org.openmrs.User)
	 */
	@Override
	public String getLastLoginTime(User user) {
		return user.getUserProperty(OpenmrsConstants.USER_PROPERTY_LAST_LOGIN_TIMESTAMP);
	}
}
