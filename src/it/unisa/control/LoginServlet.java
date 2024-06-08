package it.unisa.control;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import it.unisa.model.*;

/**
 * Servlet implementation class LoginServlet
 */
@WebServlet("/Login")
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}
			
	
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
	UserDao usDao = new UserDao();
		
		try
		{	    

		     UserBean user = new UserBean();
		     String username = request.getParameter("un");
		     String password = request.getParameter("pw");
		     
		     String hashedPassword = hashPassword(password);
		     
		     user = usDao.doRetrieve(username,hashedPassword);
			   		    
		      
		     String checkout = request.getParameter("checkout");
		     
		     if (user != null && hashedPassword.equals(user.getPassword()))
		     {
			        
		          HttpSession session = request.getSession(true);	    
		          session.setAttribute("currentSessionUser",user); 
		          
		          if(checkout!=null)
		        	  response.sendRedirect(request.getContextPath() + "/account?page=Checkout.jsp");
		          
		          else
		        	  response.sendRedirect(request.getContextPath() + "/Home.jsp");
		     }
			        
		     else 
		          response.sendRedirect(request.getContextPath() +"/Login.jsp?action=error"); //error page 
		} 
				
				
		catch(SQLException e) {
			System.out.println("Error:" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
            System.out.println("Error: Unable to hash password - " + e.getMessage());
        }
	  }
	
	    private String hashPassword(String password) throws NoSuchAlgorithmException {
	    MessageDigest md = MessageDigest.getInstance("SHA-512");
	    byte[] hashedBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
	    StringBuilder sb = new StringBuilder();
	    for (byte b : hashedBytes) {
	        sb.append(String.format("%02x", b));
	    }
	    return sb.toString();
	   }
	}
