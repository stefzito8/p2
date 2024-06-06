<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
	<link href="${pageContext.request.contextPath}/css/style.css" rel="stylesheet" type="text/css">
	<script>
     function validateForm() {
        let fields = ["nome", "descrizione", "iva", "prezzo", "dataUscita", "quantit�", "img", "piattaforma", "genere", "descDett"];
         for (let field of fields) {
             let input = document.forms["myform"][field].value;
             if (input.includes("<") || input.includes(">")) {
             alert("I caratteri < e > non sono ammessi.");
             return false;
           }
       }
        return true;
      }
      //document.getElementById('myform').onsubmit = validateForm();
    </script>
<title>Aggiungi prodotto</title>
</head>
<body>


	<%@ include file="../fragments/header.jsp" %>
	<%@ include file="../fragments/menu.jsp" %>
	
	
	<div id="main" class="clear">
	
		<h2>AGGIUNGI PRODOTTO</h2>

	<form action="../catalogo" method="post" id="myform" onsubmit="return validateForm()">
		<input type="hidden" name="action" value="add">
		<input type="hidden" name="page" value="admin/GestioneCatalogo.jsp"><br><br>
		<div class="tableRow">
			<p>Nome:</p>
			<p><input type="text" name="nome" value="" required></p>
		</div>
		<div class="tableRow">
			<p>Descrizione:</p>
			<p><input type="text" name="descrizione" value="" required></p>
		</div>
		<div class="tableRow">
			<p>Iva:</p>
			<p><input type="text" name="iva" value="" required></p>
		</div>
		<div class="tableRow">
			<p>Prezzo:</p>
			<p><input type="text" name="prezzo" value="" required></p>
		</div>		
		<div class="tableRow">
			<p>Data:</p>
			<p><input type="text" name="dataUscita" value="" required></p>
		</div>
		<div class="tableRow">
			<p>Quantit�:</p>
			<p><input type="number" name="quantit�" value="" required></p>
		</div>
		<div class="tableRow">
			<p>Immagine:</p>
			<p><input type="text" name="img" value="" required></p>
		</div>
		<div class="tableRow">
			<p>Piattaforma:</p>
			<p><input type="text" name="piattaforma" value="" required></p>
		</div>
		<div class="tableRow">
			<p>Genere:</p>
			<p><input type="text" name="genere" value="" required></p>
		</div>
		<div class="tableRow">	
			<p>Descrizione dettagliata:</p>
			<p><input type="text" name="descDett" value=""></p>
		</div>
		<div class="tableRow">
			<p></p>
			<p><input type="submit" value="aggiungi"></p>
		</div>
	</form>
	
	</div>

	<%@ include file="../fragments/footer.jsp" %>

</body>
</html>